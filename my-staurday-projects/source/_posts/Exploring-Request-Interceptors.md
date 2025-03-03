---
title: Exploring Request Interceptors
tags: [Interceptors, Cybersecurity, Golang, HTTP, Proxy]
categories: [Tech, Projects]
---
# Understanding Interceptors  

Interceptors are essential tools for monitoring and analyzing network communication, allowing cybersecurity professionals to observe how two or more computers interact. By capturing and inspecting network traffic, interceptors help in debugging, security testing, and performance analysis.  

Interception primarily happens at two key levels: **Application Layer** and **Network Layer**.  

## Application Layer Interception 
At the **Application Layer**, interception is commonly used to analyze and test **HTTP/HTTPS** protocols and **socket communication**. This helps in debugging APIs, security testing, and understanding request/response flows.  

Popular tools for application-layer interception include:  
- **Burp Suite** – A powerful tool for web security testing.  
- **ZAP (Zed Attack Proxy)** – An open-source security scanner, widely used for penetration testing.  
- **MITMproxy** – A tool specifically designed for intercepting, modifying, and analyzing HTTP/HTTPS traffic.

## Network Layer Interception
At the **Network Layer**, interception is focused on capturing and analyzing raw network traffic at a lower level. This helps in identifying vulnerabilities, tracking network behavior, and diagnosing issues.  
Key tools for network-layer interception include:  
- **Wireshark** – A widely used packet sniffer for deep network traffic analysis.  
- **tcpdump** – A command-line network packet analyzer for capturing and inspecting traffic in real time.

---

## This Saturday's Exploration
Now, as this Saturday's exploration plan is to understand how **Web Application Interception** works and maybe build a small one?  
(Well, we have a lot of **LLMs 🤖** for help… [just for help XD])

Having used **Burp Suite** (a tool used for request interception) a few years back, I am familiar with the **Proxy server concept**.

---

## Interceptors vs. Proxies: What's the Difference?
A **proxy server** acts as an intermediary that forwards requests and responses between a client (browser) and a server.  
Proxies can serve various purposes, including **caching, security, filtering, and anonymity**—not just interception.  

On the other hand, an **interceptor** is a specialized proxy that focuses on **monitoring and analyzing** network traffic.  
It captures, logs, and sometimes modifies requests and responses.  

Popular **interceptor tools** like **Burp Suite** and **ZAP** are essentially **proxies with logging and manipulation capabilities**, designed specifically for **testing and security analysis**.

For a little better explanation of proxies, check this out:  
[What is a Proxy Server?](https://www.geeksforgeeks.org/what-is-proxy-server/)

---

## Designing an HTTP/HTTPS Interceptor
With this understanding of **proxy servers**, I tried to quickly design an **HTTP/HTTPS interceptor**.  
By default, this is going to be **local**, so the **endpoint IP** will be `127.0.0.1`.

### Basic Plan
1. The **HTTP interceptor** will listen on **port 8080**.
2. **Port 8080** will be configured in **Firefox as a proxy server**, forwarding all browser requests to the interceptor.
3. The **HTTP Interceptor** should **capture requests** from the client and **cache them**.
4. The **HTTP Interceptor** should **forward the request** and **cache the response** from the server.
5. The **intercepted data** should be displayed to the user.

By just explaining what I'm trying to build, I kinda created **software requirements** 😅.

![Proxy Interception Flow](/Images/Interceptor.png)

---

## High-Level Design
The above image represents the **high-level design** and plan for the interceptor.  
At this point, I realized I wouldn’t be able to **intercept HTTPS requests** because that would mean handling **TLS/SSL encryption/decryption**.  
(This will be explored in one of the upcoming Saturdays!)

---

## Building the Interceptor in Golang
I always wanted to explore **Golang**, so I decided to build this interceptor in Go.

```go
func HandleHTTP(w http.ResponseWriter, r *http.Request, interceptedData *[]map[string]string, mu *sync.Mutex) {
    // Read the entire request body
    body, _ := io.ReadAll(r.Body)
    r.Body.Close() // Close the request body to free resources

    // Bypass Firefox captive portal detection by responding with "204 No Content"
    if r.URL.Host == "detectportal.firefox.com" {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    // Store request details in a map
    requestData := map[string]string{
        "method": r.Method,      // HTTP method (GET, POST, etc.)
        "url":    r.URL.String(), // Full request URL
        "body":   string(body),  // Request body as a string
    }

    // Create a new HTTP request using the extracted method, URL, and body
    req, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(body))
    if err != nil {
        http.Error(w, "Failed to create request", http.StatusInternalServerError)
        return
    }

    // Copy headers from the original request to the new request
    req.Header = r.Header.Clone()

    // Forward the request to the actual destination
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Println("Error:", err) // Log the error
        http.Error(w, "Failed to forward request", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close() // Ensure the response body is closed to prevent resource leaks

    // Read the response body into a byte slice
    originalRespBody, _ := io.ReadAll(resp.Body)

    // Create a copy of the response body for sending to the browser
    respBodyForBrowser := make([]byte, len(originalRespBody))
    copy(respBodyForBrowser, originalRespBody)

    // Check if the response is gzip-compressed and decompress if necessary
    if resp.Header.Get("Content-Encoding") == "gzip" {
        gzipReader, err := gzip.NewReader(bytes.NewReader(originalRespBody))
        if err != nil {
            http.Error(w, "Failed to decompress response", http.StatusInternalServerError)
            return
        }
        defer gzipReader.Close()
        originalRespBody, _ = io.ReadAll(gzipReader) // Read the decompressed response
    }

    // Extract and print the Content-Type for debugging
    contentType := resp.Header.Get("Content-Type")
    fmt.Println(requestData["url"]) // Print the request URL
    fmt.Println(contentType)        // Print the response content type

    // Dump the response headers for debugging (excluding the body)
    dump, _ := httputil.DumpResponse(resp, false)

    // Store response details in requestData for logging or interception
    requestData["response"] = html.EscapeString(string(originalRespBody)) // Escape HTML to prevent script injection
    requestData["headers"] = string(dump) // Store raw headers

    // Lock the shared data structure before modifying it (to ensure thread safety)
    mu.Lock()
    *interceptedData = append(*interceptedData, requestData) // Save request details
    mu.Unlock()

    // Copy response headers to the client response
    for k, v := range resp.Header {
        for _, val := range v {
            w.Header().Add(k, val)
        }
    }

    // Send the original response status code
    w.WriteHeader(resp.StatusCode)

    // Write the response body to the client without modification
    w.Write(respBodyForBrowser)
}

```

While running, I came across **Firefox's Captive Portal detection**.  
A **captive portal** is used in **hotels, cafes, or public Wi-Fi networks** to **authenticate users** before granting internet access.  
To read more about it: [Firefox Captive Portal](https://support.mozilla.org/en-US/kb/captive-portal).

---

## How the Interceptor Works
1. The **client (browser) sends a request** → received by the **proxy server (interceptor)**.
2. The **proxy server creates a copy of the request** and forwards it to the **actual server**.
3. The **server sends a response** → the **proxy stores it and forwards it back** to the client.

Pretty simple! Well… it **seemed simple**, but it certainly took some time to understand **Golang** and its libraries.  
There were hiccups—like **not realizing the server was encoding responses in Gzip**. I **spent half a day** just figuring out what kind of encoding the server was using when sending responses to the client. 🤦‍♂️


---

## Building the Viewer
To **view the intercepted data**, I created a **separate HTTP server** running on **port 8081** within the same Golang app.  
This **Data Viewer** server:
- Uses the **intercepted data from the proxy server (8080)**.
- Serves a **vanilla JavaScript UI** that requests data every second.
- Displays the **intercepted requests and responses** dynamically.

![Node App](/Images/NodeApp.png)  
![GIF of Intercepted Requests](/Images/HTTPInterception.gif)

---

## Wrapping Up
Though I didn’t cover all the code in this blog, you can find it on my **https://github.com/vijayanathan23/HTTPInterceptor**.

Thanks for reading from **TheSaturdayProjects** 🤖!
