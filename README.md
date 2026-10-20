# HTTP-headers-scanner
Fetch a URL once and grade its HTTP security headers A through F using the same weighted-rubric model as Mozilla Observatory.

When a browser asks a website for a page, the server sends back the page itself PLUS a bunch of metadata called "HTTP response headers." Some of those headers are security-critical: they tell the browser "only talk to me over HTTPS," "do not let other sites embed me in an iframe," "ignore guesses about file types," and more.

If a website forgets these headers, real attacks become easier: clickjacking, MIME-sniffing, mixed-content downgrades, XSS that otherwise would have been stopped by a good Content-Security-Policy.
This script connects to a URL, pulls the headers, and tells you which ones are missing or weak. 

The headers we care about:
    Strict-Transport-Security  forces HTTPS for return visits
    Content-Security-Policy    controls which scripts/styles may load
    X-Content-Type-Options     disables MIME-sniffing
    X-Frame-Options            controls iframe embedding (clickjacking)
    Referrer-Policy            limits Referer leakage
    Permissions-Policy         disables browser features the page does not need (camera, microphone, etc.)

Each rule has a severity (high / medium / low). The score is the percentage of weighted points the site earned. The grade comes from the score: 90+ A, 80+ B, 70+ C, 60+ D, otherwise F. 
This mirrors the model used by the Mozilla Observatory.

