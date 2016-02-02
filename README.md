# Apache2 PSM module

This repository contains a Apache2 module to manage a "Private State". From
HTTP1/1 you can manage a state between requests within a specific domain.
In HTTP protocol, this mechanism is also called "Cookies"; see [RFC6265](https://tools.ietf.org/html/rfc6265). So, by setting cookies
(`Set-Cookie` header) you can put and share a state between in your state-less
API(s). However anything ensure to your server that the client will not modify
the content of these cookies (a.k.a. the state itself).

This "Private State Manager" is a Apache2 module which resolve this issue.
On outgoing request, it will replace data within `Set-Cookies` headers with
a token. When PSM detect a token in `Cookie` header of incoming headers, it
will replace it with data previously set.

Let's have a look to the following schema :

```
.           GET /resources                  GET /resources
.           Cookie: t=<token>               Cookie: <data>
. ┌───────┐                       ┌───────┐                       ┌───────┐
. │  CLI  ├──────────────────────>│  PSM  ├──────────────────────>│  API  │
. └───────┘                       └───────┘                       └───────┘
.           200 OK                          200 OK
.           Set-Cookie: t=<token>           Set-Cookie: <data>
```

## Basic example

It's not clear ? Ok, assuming a HTTP client and its server.
In the following request, the server will set a cookie named "Key" with the
value "Value".

```
> GET /resource HTTP/1.1
> Host: example.net
> Accept: */*
>
< HTTP/1.1 200 OK
< Set-Cookie: Key=Value;
< Content-Length: 12
< Content-Type: text/html; charset=UTF-8
<
Hello world
```

To ensure that your cookie will not change, PSM will replace your cookie by
a token and store the data set by the server. From server point of view,
it will look exactly like the previous request. From client point of view,
it will looks like :
```
> GET /resource HTTP/1.1
> Host: example.net
> Accept: */*
>
< HTTP/1.1 200 OK
< Set-Cookie: t=aec8d9a1czyu54qx;
< Content-Length: 12
< Content-Type: text/html; charset=UTF-8
<
Hello world
```

At the next request your client will send the following request:
```
> GET /resource HTTP/1.1
> Host: example.net
> Accept: */*
> Cookie: t=aec8d9a1czyu54qx
>
```

The token will be replaced by data previously set by your server. It's coming
to the server like :

```
> GET /resource HTTP/1.1
> Host: example.net
> Accept: */*
> Cookie: Key=Value
>
```
