# pyxdw

DocuWorks 文書（`.xdw`）を読み書きする純 Python ライブラリです。

DocuWorks 本体・XDWAPI・Windows を必要とせず、Python 3.10 以上で動作します。実行時の依存パッケージはありません。個人開発のプロジェクトです。第三者由来の要素は後述の「ライセンス」に記録しています。

> **非公式ライブラリです。** 富士フイルムビジネスイノベーションとは無関係で、同社の承認・サポートを受けていません。DocuWorks は富士フイルムビジネスイノベーション株式会社の登録商標または商標です。ファイル形式は公式 DocuWorks API が書き出したファイルとの比較のみによって調べており、公開しているコードには DocuWorks のソフトウェアを逆コンパイル・逆アセンブルして得たコードやデータを含みません。

English: [README.md](README.md)

## 状況

アルファ版（0.4.0）。[docs/validation.md](docs/validation.md) に挙げたケースについて、公式 DocuWorks API 9.0.11 の出力とバイト単位で照合済みです。
動作確認は macOS（arm64）+ Python 3.14 のみで、Linux・Windows は未確認です。

## インストール

```bash
pip install git+https://github.com/norimakicode/pyxdw.git
```

PyPIでは配布していません。上記のコマンドでGitHubからインストールするか、
ローカルのチェックアウトで `python -m pip install .` を使います。

## 使い方

API は pypdf の命名に合わせています。

```python
from pyxdw import XdwReader, XdwWriter

reader = XdwReader("document.xdw")
print(len(reader.pages), reader.metadata.title)
for page in reader.pages:
    for image in page.images:          # JPEG / G3 / G4 / BMP を再圧縮せずに取り出し
        open(f"p{page.index + 1}_{image.name}", "wb").write(image.data)

with XdwWriter() as writer:
    for page in reversed(reader.pages):
        writer.add_page(page)
    writer.rotate_page(0, 90)
    writer.add_text_annotation(0, 1000, 1000, "確認済み", color=(255, 0, 0))
    writer.add_metadata({"/Title": "報告書"})
    writer.write("output.xdw")
```

コマンドライン: `pyxdw info document.xdw`（ほかに `text` `extract` `extract-page` `compact` `select` `delete` `split` `rotate` `merge`）。実行できるサンプルは [examples/](examples/) にあります。

## 機能

- 読み取り: ページ数・サイズ・回転・文書属性・アノテーションとその文字列・ページ画像
- ページ編集: コピー・並べ替え・削除・挿入・文書の結合・回転（検証済みのページ構成のみ）
- アノテーション: テキスト・付箋・矩形の追加、移動、文字列変更、削除（𠮷や絵文字など BMP 外の文字は非対応。回転したテキスト注釈の文字列変更は非対応）
- 文書属性: タイトル・ユーザー定義属性
- 非対応: 暗号化・署名付き文書、バインダー（`.xbd`）、描画（レンダリング）、OCR

未検証の結果になる操作はファイルを書かずに `XdwUnsupportedFeatureError` を送出します。詳細は [docs/](docs/) を参照してください。

## 対応形式と公開API

XDW v7・v9・v10の本体を読み取ります。ページ選択・結合・圧縮整理はv7/v10が検証対象です。
v9の書き込みには制限があり、旧世代が残ります。[互換性](docs/compatibility.md)を参照してください。

主なAPIは `pyxdw` からインポートする `XdwReader`、`XdwWriter`、`XdwPage`、
`XdwAnnotation`、`XdwError`、`XdwUnsupportedFeatureError` です。
`XdwReader` は `pages`・`metadata`・`extract_text()`、ページは `images`・`annotations`・
`extract_text()` を提供します。`XdwWriter` はページ・注釈編集、`add_metadata()`、`write()`
を提供します。公開名の全一覧は [pyxdw/__init__.py](pyxdw/__init__.py) にあります。

## 既知の制限

編集は検証済みのページ構成のみ対応し、注釈へのBMP外文字の書き込みには対応しません。
v9では `compact=True` でも履歴が残るため、過去の内容の除去には使えません。
画像抽出はページ描画ではなく、保存済みOCR文字列の読み取りはOCRの実行ではありません。
注釈回転や圧縮データの差異は [制限事項](docs/limitations.md) に記載しています。

上記サンプルには、JPEGの2ページ文書など、保護されていない検証済みの編集可能な入力が必要です。
カレントディレクトリへ画像と `output.xdw` を作成します。注釈座標の単位は0.01 mmです。

## テスト

```bash
python -m unittest discover -s tests
```

XDW のサンプルファイルは同梱していません。必要なテストは環境変数 `PYXDW_TESTDATA` が無ければスキップされます。公式 DocuWorks API による作成方法は [docs/validation.md](docs/validation.md) を参照してください。スキップ理由は外部フィクスチャの不足であり、DocuWorks本体がないためではありません。
データなしではコーデックやパーサーを検証し、文書編集の全体検証には外部フィクスチャが必要です。

## 謝辞

パブリックドメインの圧縮コード ar002 を通じて pyxdw の LZH コーデック開発に
貢献された奥村晴彦氏に、心より感謝申し上げます。

奥村氏は、[圧縮ソフトウェア開発の歴史についての記録](https://okumuralab.org/~okumura/compression/1990.html)の中で、
ソフトウェアの再配布や改変を歓迎し、次のように記しています。

> 無断転載無断改変等歓迎。

その貢献と、オープンなソフトウェア共有の精神に深く感謝します。

コードの由来についての詳細は [NOTICE](NOTICE) と
[第三者由来の情報](docs/third_party.md) を参照してください。

## ライセンス

[MIT License](LICENSE)。Copyright (c) 2026 Norimaki Code。

LZH コーデックの一部は、奥村晴彦氏がパブリックドメインとして公開した ar002 と構造が対応しており、その翻案である可能性があります。詳細は [NOTICE](NOTICE) と [docs/third_party.md](docs/third_party.md) を参照してください。
