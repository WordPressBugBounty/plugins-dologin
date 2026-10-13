# 資料生命週期

[Util](../../src/util.cls.php) 擁有 activation／uninstall 入口。解除安裝先逐站清理專屬資料，再處理安裝層級共用 usermeta；不可把 multisite 的使用者資料刪除放進逐站迴圈。

一般 `dologin_kl_*` usermeta 可依名稱判定歸屬；舊 `2fa` 名稱過於通用，只有 DoLogin 密封前綴能辨識本外掛格式。游標批次讀取後，使用原值作條件刪除，保留明文、第三方值和並發替換。WordPress 刪除 API 同時負責快取失效。不可為了清理完整而猜測明文 Base32 值。

完整資料範圍、失敗語義及測試輸入見[解除安裝規格](../../__func-uninstall.md)。此流程是管理員刪除外掛時的行為，回歸測試不會執行真實站台解除安裝。
