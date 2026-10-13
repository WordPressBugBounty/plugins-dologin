# 驗證架構與維護邊界

## 載入與責任

[autoload.php](../../autoload.php) 載入 Captcha、Captcha_State、Captcha_Local、Captcha_UI；Core 註冊既有 Auth、GUI 與 REST hooks。全域載入階段不讀 salt、不建立 challenge。

| 元件 | 責任 |
| --- | --- |
| [Captcha](../../src/captcha.cls.php) | 啟用旗標、provider、表單範圍、Turnstile server check |
| [Captcha_Local](../../src/captcha-local.cls.php) | 發行 challenge、PoW／答案校驗、ticket／preflight 狀態轉移 |
| [Captcha_State](../../src/captcha-state.cls.php) | 固定 options、容量／IP 額度、到期清理、原子 CAS |
| [Captcha_UI](../../src/captcha-ui.cls.php) | 共用元件、資源、翻譯文字 |
| [captcha.js](../../assets/captcha.js) | 操作、取消、Worker、伺服器結果 |
| [Worker](../../assets/captcha-worker.js) | 有時限的純本機 hash 搜尋，無網路或儲存 |
| [設定 template](../../tpl/captcha.tpl.php) | 方法選項、詳細 desc、相鄰預覽 |

## 請求順序

1. GUI 依 Captcha::enabled() 判定表單情境，產生元件。
2. 公開 endpoint 使用已儲存的方式，preview 需權限及 REST nonce。
3. 依 IP shard 原子檢查額度／容量後發行 challenge。
4. 預覽載入及方式切換自動開始。Worker 回報運算統計；第三次點擊或滑桿 pointer/key release 完成答案，PoW 與答案皆就緒才送出一次。PHP 檢查已存狀態、client、期限與答案；錯誤答案也消耗該題。
5. 僅公開流程取得 ticket，Auth 在密碼校驗前消耗。TOTP preflight 保留一次、綁定同組 credentials 的正式提交。

preview 共用實際判斷，但不產生登入 ticket，也不切換設定。畫面的成功文字不能成為授權依據。設定沿用既有 table／toggle；測試區右上角 refresh icon 重新建立題目。PoW 統計不進入 live region，避免持續播報；檢查結果有文字與 loading 狀態。

## 風險與測試

CAS callback 可重跑，不得有外部副作用。讀取直接走 options table，避免快取誤授權；更新後清除快取。寫入失敗或容量耗盡必須拒絕，不任意刪除未過期狀態。

每個元件擁有 Worker、fetch 與期限 timer；cancel() 處理重試、切換方式及 pagehide，generation 防止舊回應覆蓋新畫面。不要在主執行緒加入同步 hash 迴圈。status 位於 stage 之前，所有結果共用同一個頂部位置。順序圖案由 Captcha_Local 產生同一張圖與不重疊的點選區；前端只記錄位置序列，不收到文字答案對照表。SVG 仍可被程式解析，安全成本來自 PoW，不得宣稱真人保證。

新狀態在 `dologin.*` options，沿用既有解除安裝清理；舊 Turnstile continuation 未改寫儲存方式。TOTP secret、KeyLockr、passwordless token 維持獨立生命週期。

完整測試輸入與預期值見[驗證規格](../../__func-captcha.md#驗證資料與預期值)。PHP regression 覆蓋狀態邊界，Playwright fixture 使用真實 Worker／PHP 類別但模擬 WordPress API，不能充當實際 activation 或 WooCommerce 登入的證明。
