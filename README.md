# WAF Detection Tester

ブラウザベースのWAF(Web Application Firewall)検知テストツール。
[gotestwaf](https://github.com/wallarm/gotestwaf) のOWASPテストケースをベースにしたペイロードを使用し、WAFの検知能力をテストします。

> **注意**: このツールは許可されたセキュリティテスト専用です。許可なく第三者のシステムに対して使用しないでください。

## Usage

### 1. ツールを開く

`waf-tester.html` をブラウザで開きます。

```
open waf-tester.html        # macOS
xdg-open waf-tester.html    # Linux
start waf-tester.html        # Windows
```

### 2. ターゲットを設定

| 項目 | 説明 | 例 |
|------|------|----|
| Target URL / IP | テスト対象のURL or IP | `http://192.168.1.100` |
| Port | ポート番号 | `80`, `443`, `8080` |
| Path | リクエストパス | `/`, `/api/v1/search` |
| HTTP Method | HTTPメソッド | `GET`, `POST`, `PUT`, `PATCH` |
| Request Delay | リクエスト間隔 (ms) | `200` |
| Custom Headers | カスタムヘッダー (1行1つ) | `Authorization: Bearer token` |

### 3. 攻撃カテゴリを選択

以下の12カテゴリから任意に選択できます:

| カテゴリ | 内容 | ペイロード数 |
|----------|------|-------------|
| SQLi | SQLインジェクション | 15 |
| XSS | クロスサイトスクリプティング | 22 |
| RCE | リモートコード実行 | 12 |
| Path Traversal | パストラバーサル | 9 |
| Shell Injection | シェルインジェクション | 7 |
| NoSQL Injection | NoSQLインジェクション | 8 |
| XXE | XML外部エンティティ | 6 |
| SSTI | サーバーサイドテンプレートインジェクション | 7 |
| LDAP Injection | LDAPインジェクション | 5 |
| CRLF | CRLFインジェクション | 7 |
| SSI | サーバーサイドインクルード | 4 |
| Mail Injection | メールインジェクション | 4 |

### 4. エンコーディングを選択

ペイロードに適用するエンコーディングを選択します。複数選択可能で、選択した数だけリクエスト数が倍増します。

- **Plain** — エンコードなし (そのまま送信)
- **URL Encode** — URLエンコード
- **Double URL** — 二重URLエンコード
- **Base64** — Base64エンコード
- **Unicode** — Unicodeエスケープ

### 5. インジェクションポイントを選択

ペイロードを挿入する箇所を指定します:

- **Body Parameter** — `test=<payload>` としてリクエストボディに挿入
- **URL Parameter** — `?test=<payload>` としてURLクエリに挿入
- **Header** — `X-Test: <payload>` ヘッダーに挿入
- **Cookie** — `Cookie: test=<payload>` に挿入
- **URL Path** — URLパスの末尾に挿入

### 6. テスト実行

**Start Test** をクリックするとテストが開始されます。

- リアルタイムでプログレスバーと統計情報が更新されます
- 各リクエストの結果は **Blocked** / **Passed** / **Error** に分類されます
- **Stop Test** でいつでも中断できます

### 7. 結果の確認・エクスポート

- **All / Blocked / Passed** ボタンで結果をフィルタリング
- **Export CSV** で結果をCSVファイルとしてダウンロード

## 判定ロジック

| レスポンス | 判定 |
|-----------|------|
| HTTP 403, 406, 429, 493 | Blocked |
| HTTP 5xx | Blocked |
| レスポンスボディに `blocked`, `forbidden`, `denied`, `waf` 等を含む | Blocked |
| 上記以外の正常レスポンス | Passed |
| ネットワークエラー / タイムアウト | Error |

## 制約事項

- ブラウザの `fetch` API を `no-cors` モードで使用するため、異なるオリジンへのリクエストではレスポンスの詳細 (ステータスコード・ボディ) が取得できない場合があります
- より正確なテスト結果を得るには、テスト対象と同一オリジンに配置するか、プロキシ経由での利用を推奨します
- HTTPS対象に対してHTTPページから送信する場合、Mixed Contentブロックが発生する可能性があります
