extern crate hmac_sha256;
extern crate reqwest;
extern crate base64;

use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::Client;
use reqwest::Response;
use hmac_sha256::HMAC;
use std::error::Error;
use chrono::prelude::Utc;

fn canonicalized_headers(headers: &HeaderMap) -> String {
    let mut ms_headers = Vec::new();
    for (key, value) in headers.iter() {
        if key.as_str().starts_with("x-ms-") { // key.as_str() is lower case
            ms_headers.push((key.as_str(), value));
        }
    }
    ms_headers.sort();
    
    let mut ret = String::new();
    for (header_name, header_value) in ms_headers {
        ret += &format!("{}:{}\n", header_name, header_value.to_str().unwrap_or(""));
    }
    ret
}

#[derive(Debug)]
struct AzureRejectionError {
    code: u16,
    details: String,
}

impl Error for AzureRejectionError {
    fn description(&self) -> &str {
        &self.details
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl std::fmt::Display for AzureRejectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Azure rejected request: {}", self.details)
    }
}

fn canonicalized_resource(account: &str, path: &str) -> String {
    format!("/{}{}", account, path)
}

fn header_str<'a>(headers: &'a HeaderMap, key: &'static str) -> &'a str {
    headers.get(key).and_then(|x| x.to_str().ok()).unwrap_or("")
}

fn build_authorization(method: &str, account: &str, path: &str, headers: &HeaderMap, key: &str) -> String {
    let to_sign = format!("{method}\n{content_encoding}\n{content_language}\n{content_length}\n{content_md5}\n{content_type}\n{date}\n{if_modified_since}\n{if_match}\n{if_none_match}\n{if_unmodified_since}\n{range}\n{headers}{resource}",
        method = method,
        content_encoding = header_str(headers, "Content-Encoding"),
        content_language = header_str(headers, "Content-Language"),
        content_length = header_str(headers, "Content-Length"),
        content_md5 = header_str(headers, "Content-MD5"),
        content_type = header_str(headers, "Content-Type"),
        date = header_str(headers, "Date"),
        if_modified_since = header_str(headers, "If-Modified-Since"),
        if_match = header_str(headers, "If-Match"),
        if_none_match = header_str(headers, "If-None-Match"),
        if_unmodified_since = header_str(headers, "If-Unmodified-Since"),
        range = header_str(headers, "Range"),
        headers = canonicalized_headers(headers),
        resource = canonicalized_resource(account, path));
    let key_bytes = match base64::decode(key) {
        Ok(key_bytes) => key_bytes,
        Err(_) => {
            return String::new();
        }
    };
    let mac_bytes = HMAC::mac(to_sign.as_bytes(), &key_bytes);
    format!("SharedKey {}:{}", account, base64::encode(&mac_bytes))
}

pub struct Container {
    pub account: String,
    pub shared_key: String,
    pub container: String,
}

fn handle_rejection(response: &mut Response) -> Result<(), Box<dyn Error>> {
    let status = response.status();
    if status.is_success() {
        Ok( () )
    } else {
        Err(AzureRejectionError{
            code: status.as_u16(), 
            details: format!("Status {}\nResponse text: {}", status, response.text()?)
        }.into())
    }
}

impl Container {
    pub fn put_blob(&self, name: &str, content: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-date", HeaderValue::from_str(&Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string())?);
        headers.insert("x-ms-version", HeaderValue::from_static("2015-02-21"));
        headers.insert("x-ms-blob-type", HeaderValue::from_static("BlockBlob"));
        headers.insert("Content-Length", HeaderValue::from_str(&format!("{}", content.len())).unwrap());
        
        let path = format!("/{}/{}", self.container, name);
        let authorization = build_authorization("PUT", &self.account, &path, &headers, &self.shared_key);
        
        headers.insert("Authorization", HeaderValue::from_str(&authorization)?);
        
        let mut response = Client::new().put(&format!("https://{}.blob.core.windows.net{}", self.account, path))
            .headers(headers)
            .body(content.to_vec())
            .send()?;
        handle_rejection(&mut response)?;
        Ok( () )
    }



    pub fn get_blob(&self, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-date", HeaderValue::from_str(&Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string())?);
        headers.insert("x-ms-version", HeaderValue::from_static("2015-02-21"));
        
        let path = format!("/{}/{}", self.container, name);
        let authorization = build_authorization("GET", &self.account, &path, &headers, &self.shared_key);
        
        headers.insert("Authorization", HeaderValue::from_str(&authorization)?);
        
        let mut response = Client::new().get(&format!("https://{}.blob.core.windows.net{}", self.account, path))
            .headers(headers)
            .send()?;
        handle_rejection(&mut response)?;
        let mut response_body = Vec::new();
        response.copy_to(&mut response_body)?;
        Ok( response_body )
    }
}

#[cfg(test)]
mod tests {
    use crate::{Container};
    use std::env;
    use std::time::SystemTime;
    
    fn make_container() -> Container {
        Container {
            account: env::var("azure_account").expect("Missing azure_account environment variable"),
            shared_key: env::var("azure_key").expect("Missing azure_key environment variable"),
            container: env::var("azure_container").expect("Missing azure_container environment variable"),
        }
    }
    
    #[test]
    fn test_get_put_consistency() {
        let container = make_container();
        let contents = format!("This file was uploaded at timestamp {} to test the azure_blob crate", 
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
            
        container.put_blob("azure_blob_test.txt", contents.as_bytes()).unwrap();
        
        let blob = container.get_blob("azure_blob_test.txt").unwrap();
        assert_eq!(String::from_utf8(blob).unwrap(), contents);
    }
}
