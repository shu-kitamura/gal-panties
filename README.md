# ギャルのパンティおくれ

ドラゴンボールの「ギャルのパンティおくれ」を eBPF を使って再現するプロジェクトです。  

## 登場人物(プログラム)

- `shenron`: サーバプログラム
- `pilaf`: クライアントプログラム
- `woolong`: eBPF プログラム

shenron と pilaf の通信に woolong が横入りします。（shenron, pilaf, woolong はプロセスです）  
以下のような通信が発生します。  

1. pilaf が shenron に「いでよドラゴン」というパケットを送信
2. shenron が pilaf に「願いを言え。どんな願いもひとつだけ叶えてやろう」というパケットを送信
3. woolong が「2」のパケットのペイロードを「ギャルのパンティおくれーーーーーーっ！！！！！」に書き換えて、送り返す。

## 環境

- Linux 環境（動作確認は Ubuntu 24.04 で実施）
- Rust
- [Development Environment](https://aya-rs.dev/book/start/development/)を参照して、必要なツールをインストールしてください。  

## 実行手順

1) サーバ・クライアントホストで、`cargo build` を実行
2) サーバ側ホストで `shenron` を実行
   ```
   ./target/debug/shenron -i <インタフェース>
   ```
3) クライアント側ホストで `woolong` を実行
   ```
   sudo ./target/debug/woolong -i <インタフェース> &
   ```
4) クライアント側ホストで `pilaf` を実行
   ```
   ./target/debug/pilaf -a <サーバのIPv4>
   ```

※ `-i` を指定しない場合、`eth0` が使用されます。


## デモ

eBPFプログラムなし/ありで実行したデモ動画です。  

### eBPF なし

クライアント側で入力した内容が、サーバ側に表示されます。  
その後、「たやすい願いだ」が表示されます。  

![without-ebpf](./demo/without_ebpf.gif)

### eBPF あり

「ギャルのパンティおくれ」が、サーバ側に表示されます。  
その後、「たやすい願いだ」が表示されます。  

![with-ebpf](./demo/with_ebpf.gif)

## 注意点

- ドライバが XDP_TX をサポートしていない場合は、SKB モードでの動作や別の NIC を検討してください。  
  SKBモードを使用する場合、`woolong/src/main.rs`の以下のように変更してください。
  ```diff
  -     program.attach(&iface, XdpFlags::default())
  +     program.attach(&iface, XdpFlags::SKB_MODE)
  ```
