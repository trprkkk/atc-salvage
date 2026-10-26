# atc-salvage

AttacheCase（.atc, Ver.2.x）の暗号化アーカイブが、ファイル破損（不良セクタなど）で
途中まで展開できなくなったときに、**壊れていない部分をできるだけ取り出す**ためのツールです。
パスワードは必要です（このツールはパスワードを推測しません）。

> English summary: Best-effort salvage tools for AttacheCase Ver.2.x `.atc` archives
> that fail partway through decryption/decompression because the file is damaged.
> Needs the password. Recovery is heuristic: the format has no per-file checksum, so
> "OK" means "decoded without error", not "proven intact". See *Limitations*.

## 何ができて、何ができないか

| 状況 | 結果 |
|---|---|
| 壊れた場所より前のファイル | 完全に取り出せます（`salvage_extract`） |
| 壊れた場所より後のファイル | 単純な方法では取り出せません。`dump_body` + `resync_recover.py` で、無圧縮ブロックの継ぎ目を探して再開を試みます |
| 壊れた範囲そのもの | 取り出せません。ゼロ埋めで位置だけ保ちます |

AttacheCase の本体は、全ファイルを1本の連続した deflate ストリームに圧縮しています。
そのため、途中の1バイトが壊れると、通常のデコーダはそこで止まります。
本ツールは、JPEG など既に圧縮済みのデータが多く格納される「無圧縮（STORED）ブロック」の
境界（長さ LEN と その反転 NLEN の組）を手がかりに、そこから再開します。

## 必要なもの

- C++11 コンパイラ（g++ など）と zlib の開発ヘッダ（Debian/Ubuntu: `sudo apt install build-essential zlib1g-dev`）
- Python 3.7 以降（テストスイートが `capture_output` を使用するため。標準ライブラリのみ使用。開発時は 3.12 で確認）
- Linux / WSL（テストは Linux で実施）。Windows の場合は WSL の利用を推奨します。

## ビルドとテスト

```sh
make          # bin/salvage_extract, bin/dump_body を作成
make test     # テスト一式を実行（合成アーカイブを生成して検証）
```

## 使い方

### 1. まず、壊れていない部分を取り出す

```sh
./bin/salvage_extract 入力.atc "パスワード" 出力フォルダ
```

終了コードが 0 なら、全ファイルがエラーなく展開されました。
3 の場合は途中で壊れており、ログに従って次の手順に進みます。

### 2. 壊れた部分より後を試す（時間がかかることがあります）

```sh
./bin/dump_body 入力.atc "パスワード" body.bin manifest.json
python3 src/resync_recover.py body.bin manifest.json 出力フォルダ2 --max-skip 20000000
```

- `--max-skip` は、壊れた地点から何バイト先まで継ぎ目を探すかです。既定値は小さすぎることが多く、
  大きく壊れている場合は 2,000,000 ～ 80,000,000 程度が必要になることがありました。
  範囲の走査は直線的に増えるため、大きくするほど時間がかかります。
- 途中の処理（デコード、継ぎ目の特定）には、大きなアーカイブでは数分かかる場合があります。
  進捗はログに出るので、止まっているように見えても確認できます。
- 処理の最後に、次のような集計を表示します（数字は例です）。

```
Done. 60 corrupted region(s) bridged.
  Decoded data: 500000000 / 528686183 bytes (94.5%); 28686183 bytes unrecoverable (zero-filled).
  Files: 4000 OK, 60 GAP (overlap a lost region), 2 PART, 0 not written.
```

### ログの見方

| 表示 | 意味 |
|---|---|
| `[ OK ]` | エラーなく展開できた。**破損していないことの証明ではありません** |
| `[GAP ]` | 破損（ゼロ埋め）した範囲と重なる。中身は不完全です |
| `[PART]` | 破損の直前まで。末尾は不完全です |
| `Unrecoverable byte ranges` | ゼロ埋めされた範囲と、影響を受けるファイル名の一覧 |

## 限界（必ず読んでください）

- **ファイル単位のチェックサムがありません。** `[ OK ]` のファイルでも、
  破損がファイルの内部だけに収まっている場合は検出できません。
  破損範囲の前後 1〜2 ファイルは、専用ソフトなどで目視確認してください。
- **ファイル名と中身の対応は、シグネチャを確認できる形式でのみ検証しています**
  （jpg/jpeg/png/gif/bmp/mp4/mov/m4v/pdf/zip/docx/xlsx/pptx）。
  それ以外の拡張子では、破損後の中身がどのファイルに属するかは確認できません。
  ツールは起動時に該当件数を警告します。
- **ヒューリスティックです。** 正しさも網羅性も保証しません。
- 復元できなかった範囲は、ゼロ埋めで位置を保っています。ファイルの中身は
  その範囲だけ欠けています。

## 仕組み（簡単に）

1. `dump_body`: 正しいパスワードで本文を復号し、圧縮済みのまま1つのファイルに書き出します。
   同時に、各エントリの名前・サイズ・順序を JSON にします。パスワードや暗号処理は
   Python 側には入りません。
2. `resync_recover.py`:
   - zlib で先頭から復号し、エラーの直前まで取り出します。
   - 取り出した各ファイル境界が、シグネチャで正しいかを確認し、怪しい部分を戻します。
   - 壊れた地点の後ろで、LEN == ~NLEN を満たす無圧縮ブロックの候補を探します。
   - 候補は、(a) 一定量を誤りなく復号でき、(b) マニフェストのファイル配置と
     一致する（次の数ファイルのシグネチャも確認）ものだけを採用します。
   - 採用した継ぎ目から、直前の 32KB を辞書として復号を再開します。
   - 失われた範囲の大きさは、ヘッダに書かれたファイルサイズの合計から決めます（推定ではありません）。

## ライセンスと出典

本ツールは [h2so5/libatc](https://github.com/h2so5/libatc)（zlib 系ライセンス）を基にしています。
改変した箇所には、各ファイル先頭に注記を入れています。詳細は `THIRD_PARTY_NOTICES.md` を参照してください。
ツール本体（`src/`）のライセンスは、公開前に作者が決めて `LICENSE` ファイルとして追加してください（未設定）。

AttacheCase は HiBARA Software 作成のソフトウェアです。このツールは同ソフトとは無関係の
第三者による解析ツールです。
