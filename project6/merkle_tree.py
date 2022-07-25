

from hashlib import sha256 

def max_power2(n):
    """
    用来获得比n小的最大的2次幂
    """
    k = 1
    while k < n :
        k = k<<1
    return k >>1

class MerkleTree():
    
    def addLeaf(self, string):
        """
        添加叶子节点，注意hash的时候前面+0x00
        """
        h = sha256(b'\x00'+str(string).encode('utf-8')).digest()
        self.size += 1
        self.hashtree[(self.size-1,self.size)]=h
        

    def mth(self, k1, k2):
        """ 
        能够递归的创建merkletree
        注意此处加盐为0x01
        """
        try:
            node_h = self.hashtree[(k1,k2)]
        except KeyError as v:   
            k = k1 + max_power2(k2-k1)
            node_h = sha256(b'\x01' + self.mth(k1, k) + self.mth(k,k2)).digest()
            self.hashtree[(k1,k2)]=node_h
        return node_h

    def auditPath(self, m, n=None):
        """
        返回存储d(m)到根节点的最短路径的列表
        """

        if not n: n = self.size
        def _auditPath(m, k1, k2):
            if (k2-k1) == 1:
                return [ ] 
            k = k1 + max_power2(k2-k1)
            if m < k:
                path = _auditPath(m, k1, k) + [self.mth(k,k2),]
            else:
                path = _auditPath(m, k, k2) + [self.mth(k1,k),]
            return path
        
        return _auditPath(m, 0, n)

    def Proof(self, m, n, leaf_hash, root_hash, audit_path):
        """ 
        根据上一个函数的得到的audit_path来证明的d(m)对应的叶子节点确实存在
        此处仍然需要注意加盐
        """
        
        def _SubProof(m, k1, k2, i):
            
            if len(audit_path) == i:
                return leaf_hash
            k = k1 + max_power2(k2-k1)
            ithAuditNode = audit_path[len(audit_path) - 1 - i]
            if m < k:
                hv = sha256(b'\x01' + _SubProof(m, k1, k, i+1) + ithAuditNode ).digest()
            else:
                hv = sha256(b'\x01' + ithAuditNode + _SubProof(m, k, k2, i+1) ).digest()
            return hv
           
        hv = _SubProof(m, 0, n, 0)        
        return hv == root_hash
    
    def rootHash(self, n=None):
        """ 
        merkle树根节点的哈希值
        """
        if not n: n = self.size
        if n > 0:
            return self.mth(0, n)
        else:
            return sha256(''.encode('utf-8')).digest()  
            
    def leafHash(self, m):
        """ 
        用来查看d(m)对应的hash值
        """
        return self.mth(m, m+1)
            
     
    def __init__(self):
        """
        初始化，并建立一个字典来存储merkletree
        """
        self.size = 0
        self.hashtree = {} 
        


#----------------test---------------------

tree1=MerkleTree()
n=10
for i in range(0,n):#创造一个叶子结点数为10w的merkle数
    tree1.addLeaf(str(i))
for i in tree1.hashtree.keys():
    print(i,":",tree1.hashtree[i])


tree2=MerkleTree()
n=100000
#d(0),d(1),....d(n-1)
for i in range(0,n):#创造一个叶子结点数为10w的merkle数
    tree2.addLeaf(str(i))

print("根节点的hash：",tree2.mth(0,n))#为了递归的计算出根节点的hash值

path1=tree2.auditPath(3)#获得d（3）到根节点的最短路径
#print(path1)

print(tree2.Proof(3,n,tree2.leafHash(3),tree2.rootHash(),path1))#根据上述路径判定d（3）是否在merkle树当中





