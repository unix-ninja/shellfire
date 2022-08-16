# Shellfire PHP Test App  

The `./src` directory contains a very simple set of scripts that make up a 
basic vulnerable application. A `Dockerfile` and `docker-compose.yml` file is 
available to use for your convenience.  


### Vulnerabilities  

- `include` LFI  
- `include` RFI  
- `file_get_contents` SSRF  
- `cURL` SSRF  

### Usage  

- `cd ./docker/php`  
- `docker-compose up`  
- Navigate to `http://localhost:8089` and start playing around.  

