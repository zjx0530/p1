# merkle tree

  本python脚本根据RFC6962编写了MerkleTree 类，并设计了包括添加叶子节点，计算对应节点的hash值等方法。

  首先我们拥有一组输入，分别为d（0），d（1）.....  以他们的加盐后的hash（0x00||d）作为对应的叶子节点的hash值。然后再往上计算其他节点的hash（0x01||hi||hj）。其中hi和hj应当是指向同一个父节点的节点的hash值。

  我们利用字典来存储merkle树，其中键为（k1,k2）,每一个节点对应的键的设计如下图范例

![在](.\1.png)

  实现了叶节点的存在性证明，但是没有设计

  测试方法：已经写在脚本的最下方，产生了10w叶节点的merkletree，并且验证了d（10）的存在

参考资料：

1. [Merkle Tree 实现细节及（不）存在性证明_跨链技术践行者的博客-CSDN博客](https://blog.csdn.net/shangsongwww/article/details/85339243)

2. [Merkle树算法解析及python实现_谨墨的博客-CSDN博客_merkle树 python](https://blog.csdn.net/weixin_43137080/article/details/115653424)

3. [GitHub - nymble/merkletree at 893c9e955f69d99692ef64b99098f6db8b4fd207](https://github.com/nymble/merkletree/tree/893c9e955f69d99692ef64b99098f6db8b4fd207)