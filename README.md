# apiproxy

## Mở đầu

Nhiều công ty không cho phép AI agent (Claude, Copilot, hay bất kỳ coding
assistant nào) được thấy token/API key thật, nhưng agent lại cần chạy
integration test chống lại một API thật. `apiproxy` giải quyết việc đó bằng
một reverse proxy chạy local: nó giữ token, tự thêm header `Authorization`
vào mỗi request, và agent chỉ bao giờ thấy một địa chỉ loopback như
`http://127.0.0.1:8787/orders`.

```
AI agent / test suite
        |
        |  http://127.0.0.1:8787/orders/v1/items   (không có token)
        v
   apiproxy (giữ token, đã mã hoá at rest trên Windows)
        |
        |  https://api.corp.internal/orders/v2/v1/items
        |  Authorization: Bearer <token>            (agent không thấy)
        v
   upstream thật
```

Token không bao giờ nằm trong test code, repo, biến môi trường của agent,
hay bất kỳ response mà agent đọc được.

## Build

```
make windows   # cross-compile ra bin/apiproxy.exe (Windows amd64)
make build     # build binary cho máy hiện tại (macOS/Linux)
make test      # go test ./... -race
make check     # gofmt check + vet + test
```

`make windows` cross-compile thẳng từ macOS/Linux (`GOOS=windows
GOARCH=amd64 CGO_ENABLED=0`), không cần máy Windows hay Go runtime nào trên
máy đích — chỉ cần copy `bin/apiproxy.exe` sang là chạy được.

Vì file `.exe` chưa được ký (unsigned), lần chạy đầu trên Windows sẽ gặp
cảnh báo SmartScreen ("Windows protected your PC"). Đây là cảnh báo bình
thường cho binary tự build, không phải lỗi — chọn "More info" rồi "Run
anyway".

## Bắt đầu nhanh

```
apiproxy init
```

Lệnh này tạo file config mẫu (xem đường dẫn thật ở mục Cấu hình bên dưới):

```toml
# apiproxy route table.
# This file holds NO secrets and is safe to commit.
# Tokens are stored encrypted; add one with: apiproxy login <profile>

listen = "127.0.0.1:8787"

# Requests to http://127.0.0.1:8787/orders/... are forwarded to the upstream
# below with an "Authorization: Bearer <token>" header injected.
[[route]]
alias    = "orders"
upstream = "https://api.corp.internal/orders/v2"
profile  = "corp-sso"
scheme   = "Bearer"
```

Sửa `upstream` cho đúng API thật của bạn, rồi lưu token:

```
apiproxy login corp-sso
```

Lệnh này hỏi token (ẩn, không echo ra terminal, không vào shell history),
rồi hỏi một passphrase tuỳ chọn để bảo vệ thêm. Sau đó chạy proxy:

```
apiproxy serve
```

Output thật trông như sau:

```
apiproxy listening on http://127.0.0.1:8787
while running, tokens are held in memory and readable by any process under your user account.

routes:
  /orders           -> https://api.corp.internal/orders/v2

debug endpoints:
  http://127.0.0.1:8787/_proxy/health
  http://127.0.0.1:8787/_proxy/routes
  http://127.0.0.1:8787/_proxy/requests

API_BASE_URL=http://127.0.0.1:8787/orders
```

Đưa dòng `API_BASE_URL=...` đó cho test suite hoặc cho agent, thế là xong —
không ai cần biết token thật.

## Cấu hình

File config không chứa secret nào, có thể commit vào repo của team bình
thường. Mặc định ở:

- Windows: `%AppData%\apiproxy\config.toml`
- macOS/Linux: theo `os.UserConfigDir()` (ví dụ `~/Library/Application
  Support/apiproxy/config.toml` trên macOS)

Có thể override bằng flag `-config <path>` trên mọi subcommand.

| Key | Ý nghĩa |
|---|---|
| `listen` | Địa chỉ `host:port` để lắng nghe. Phải là loopback (`127.0.0.1`, `::1`, hoặc `localhost`) — mặc định `127.0.0.1:8787`. Bind ra ngoài loopback sẽ bị từ chối ngay khi load config, vì proxy giữ một credential sống. |
| `[[route]] alias` | Segment đầu của path, ví dụ `orders` ứng với `http://127.0.0.1:8787/orders/...`. Chỉ chấp nhận chữ thường, số, `-`, `_`. Không được đặt là `_proxy` — tên này dành riêng cho các endpoint debug của proxy. |
| `[[route]] upstream` | Base URL cố định mà request được forward tới. Cố định tại thời điểm load config: không request nào có thể thay đổi đích đến. |
| `[[route]] profile` | Tên entry trong secret store chứa token của route này. Để trống nếu route không cần credential. |
| `[[route]] header` | Header sẽ chứa credential. Mặc định `Authorization`. |
| `[[route]] scheme` | Prefix cho giá trị header, ví dụ `Bearer` cho ra `Authorization: Bearer <token>`. Để trống thì gửi token thô. |

Path được nối bằng cách lấy phần path còn lại sau alias rồi ghép vào cuối
path của `upstream`. Ví dụ với alias `orders`, upstream
`https://api.corp.internal/orders/v2`, request gửi tới
`/orders/v1/items` sẽ đi tới:

```
https://api.corp.internal/orders/v2/v1/items
```

## Dùng trong test

Project này chưa có integration test, nên hãy thiết kế test suite với một
base URL có thể inject được ngay từ đầu — đừng hard-code domain thật ở bất
kỳ đâu. Chạy `apiproxy serve`, lấy dòng `API_BASE_URL` từ banner (hoặc tự
build từ `cfg.Listen` + alias), và truyền nó vào test qua biến môi trường
hoặc config của test runner:

```
export API_BASE_URL=http://127.0.0.1:8787/orders
go test ./...
```

Test suite gọi `$API_BASE_URL/v1/items` như gọi API thật — không cần biết
gì về token, scheme, hay header injection. Agent chạy test cũng chỉ thấy
đúng URL đó.

## Các endpoint `/_proxy`

Mọi request dưới `/_proxy/` được proxy tự trả lời, **không bao giờ** forward
lên upstream — nên không có đường nào để credential lọt qua các endpoint
này.

| Endpoint | Trả về | Dùng để |
|---|---|---|
| `GET /_proxy/health` | `{"status":"ok","uptime_s":<float>}` | Kiểm tra proxy còn sống trước khi chạy test. |
| `GET /_proxy/routes` | Danh sách route: `alias`, `upstream`, `profile`, `header`, `has_token`, `fingerprint`, `issuer`, `expires_at`, `expired` | Xem route nào có token, token nào sắp/đã hết hạn — không bao giờ có giá trị token thật. |
| `GET /_proxy/requests?n=<N>` | `{"events":[...], "dropped":<uint>}`, mỗi event có `alias`, `method`, `in_path`, `out_url`, `status`, `duration_ms`, `resp_bytes`, `injected`, `error` | Xem request gần nhất đã đi đâu, status code upstream trả về, và quan trọng nhất: `injected` có `true` hay không. |

`injected: true/false` là tín hiệu quyết định khi debug: nó phân biệt "test
tôi viết sai" (request đi đúng, upstream trả lỗi logic) với "proxy không
gắn credential" (request đi ra mà không có `Authorization`). Agent có thể
tự gọi `/_proxy/requests` để biết điều này mà không cần hỏi người, và không
cần thấy token để biết.

Tương tự, `fingerprint`/`issuer`/`expires_at` ở `/_proxy/routes` giải thích
một lỗi 401 bất ngờ (token hết hạn, hoặc token đang nạp không phải token
bạn nghĩ) mà không hề để lộ giá trị token.

## Bảo mật — đọc phần này

**Những gì proxy bảo vệ được:**

- Token không bao giờ nằm trong test code, repo, biến môi trường của agent,
  hay bất kỳ response nào agent đọc được.
- Upstream của mỗi route cố định tại thời điểm load config; không request
  nào (Host header, absolute-form URI, query param...) có thể đổi đích đến
  — proxy không thể bị biến thành open relay để leak token ra host khác.
- Header client tự gửi lên (`Authorization`, `Cookie`,
  `X-Forwarded-For/Host/Proto`, `Proxy-Authorization`, `Forwarded`) bị xoá
  trước khi credential thật được gắn vào, nên client không thể giả mạo hay
  "seed" trước giá trị của chính header đó.
- `/_proxy/*` không bao giờ được forward lên upstream, nên không có cách
  nào để request đến các endpoint debug mang theo credential ra ngoài.
- Proxy chỉ bind loopback (`127.0.0.1`/`::1`/`localhost`), kèm kiểm tra Host
  header ở tầng guard riêng để chặn DNS rebinding — hai lớp, không chỉ dựa
  vào việc bind loopback.

**Những gì proxy KHÔNG bảo vệ được** (đây là phần không được phép nói nhẹ
đi): trong lúc `apiproxy serve` đang chạy, token nằm dưới dạng plaintext
trong memory của chính process đó, suốt thời gian proxy sống. Trên Windows,
bất kỳ process nào chạy dưới **cùng user Windows** đều có thể đọc được nó
bằng `OpenProcess` + `ReadProcessMemory`, không cần quyền đặc biệt nào.
DPAPI và passphrase chỉ bảo vệ token **ở trạng thái lưu trữ** (at rest) —
tức là blob bị copy ra khỏi máy, bị user Windows khác đọc, hoặc lọt qua
repo/backup/roaming profile sync. DPAPI `CurrentUser` là ranh giới theo
*user*, không phải theo *process*, và không có gì trong proxy thay đổi
được điều đó khi `serve` đang chạy.

Nếu agent của bạn tuyệt đối không được có khả năng lấy được token (dù chỉ
trên lý thuyết), same-user là không đủ: hãy chạy agent dưới một OS user
riêng, một container, hoặc một VM. Same-user chỉ là một tư thế tiện lợi
(convenience posture), không phải một ranh giới bảo mật.

Biến môi trường `APIPROXY_PASSPHRASE` (dùng cho `login` không tương tác và
cho `serve` bỏ qua prompt) tiện cho CI/script, nhưng đặt passphrase vào môi
trường của process khiến nó đọc được bởi process khác chạy cùng user —
đánh mất toàn bộ lớp bảo vệ at-rest mà passphrase mang lại. `apiproxy` sẽ
in cảnh báo ra stderr mỗi khi nó đọc passphrase từ biến này; ưu tiên dùng
prompt tương tác khi có thể.

Trên macOS/Linux, `serve` không có DPAPI để dùng nên rơi vào "dev mode": đọc
token thẳng từ biến môi trường `APIPROXY_TOKEN_<PROFILE>` (không mã hoá,
không encrypted storage nào cả). Mode này chỉ để smoke-test chính proxy
trên máy dev, không phải để giữ credential thật.

## Lệnh và flag

| Lệnh | Flag | Mặc định | Ý nghĩa |
|---|---|---|---|
| `init` | `-config <path>` | user config dir | Đường dẫn ghi `config.toml`. |
| | `-force` | `false` | Ghi đè nếu file đã tồn tại. |
| `login <profile>` | `-config <path>` | user config dir | Dùng để cảnh báo nếu `profile` không được route nào tham chiếu. |
| | `-secrets <dir>` | user cache dir | Thư mục chứa blob token đã mã hoá. |
| `logout <profile>` | `-secrets <dir>` | user cache dir | Thư mục chứa blob token đã mã hoá. |
| `status` | `-config <path>` | user config dir | Config để đọc danh sách route. |
| | `-secrets <dir>` | user cache dir | Thư mục chứa blob token đã mã hoá. |
| `serve` | `-config <path>` | user config dir | Config để load route table. |
| | `-secrets <dir>` | user cache dir | Thư mục chứa blob token đã mã hoá. |
| | `-listen <addr>` | (dùng `listen` trong config) | Ghi đè địa chỉ listen; vẫn phải là loopback. |
| | `-history <n>` | `200` | Số request gần nhất giữ lại cho `/_proxy/requests`. |
| | `-timeout <dur>` | `30s` | Timeout chờ upstream bắt đầu trả response header (không tính thời gian stream body). |
| | `-quiet` | `false` | Tắt log mỗi request ra stdout. |
| | `-no-auth-prompt` | `false` | Bỏ qua prompt passphrase (profile có passphrase sẽ decrypt lỗi). |
| mọi lệnh | `-h` / `-help` / `--help` / `help` | | In usage. |
| | `-version` / `--version` / `version` | | In phiên bản build. |

## Xử lý sự cố

| Tình huống | Thông báo thật | Cách xử lý |
|---|---|---|
| Sai passphrase khi `serve` | `profile "X": passphrase looks wrong: secret: cannot decrypt (wrong passphrase, or blob not created by this user on this machine)` | Nhập lại đúng passphrase đã dùng lúc `login`. |
| Profile chưa có token lưu | `profile "X" has no stored token; run: apiproxy login X` | Chạy `apiproxy login <profile>`. |
| `-listen` không phải loopback | `config: listen host "X" is not loopback; apiproxy holds a live credential and must not be reachable off-machine` | Dùng `127.0.0.1`, `::1`, hoặc `localhost`. |
| Token đã hết hạn | Không có lỗi cứng khi `serve`, nhưng upstream sẽ trả 401. Xem `/_proxy/routes`, field `expired: true` và `expires_at`. | `apiproxy login <profile>` lại với token mới. |
| Gọi alias không tồn tại | HTTP 404, body `not found` (không liệt kê alias nào đang có, để tránh lộ danh sách integration nội bộ) | Kiểm tra lại alias trong URL so với `config.toml`. |
| Path chứa `..` (path traversal) | HTTP 400, body `invalid path` | Không có gì cần sửa phía proxy; đây là request bị chặn đúng thiết kế. |
| Upstream không kết nối được / timeout | HTTP 502, body `upstream unavailable` | Kiểm tra `upstream` trong config và kết nối mạng tới host đó; xem `/_proxy/requests` field `error` (`upstream timeout` hoặc `upstream transport error`). |
| Không lấy được token để gắn vào request | HTTP 503, body `proxy: could not obtain token for profile "X"` | Thường do passphrase sai hoặc blob bị hỏng; chạy lại `apiproxy login <profile>`. |
