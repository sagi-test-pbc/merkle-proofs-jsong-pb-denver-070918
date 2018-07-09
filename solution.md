
# Merkle Proofs


```python
# Merkle Proof Example
from block import Block, Proof
from helper import int_to_little_endian, merkle_path

hex_tx_hashes = [
    "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
    "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
    "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
    "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
    "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
    "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
    "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
    "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
    "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
    "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
    "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
    "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
    "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
    "8e694f5092f6a644ab587ca445f9e949e4f5991d3c3c72bd4574a7c9896a2402",
    "9cc887977168f430f4f896dfc6fc7379834733ce938abe7cd8a1a668d1ea1841",
]
tx_hash = bytes.fromhex('9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab')
b = Block(
    version=536870914,
    prev_block=bytes.fromhex('00000000000002dda81fd83ac5b944ad88592a213bfaf54bffad68725c782639'),
    merkle_root=bytes.fromhex('f2710c8f3652ec6bfe79769458ae4be8117cad46964ce9dab9ce570bcb2ff9b0'),
    bits=int_to_little_endian(437256176, 4),
    nonce=b'\x00\x00\x00\x00',
    timestamp=1512503014,
    tx_hashes=[bytes.fromhex(h) for h in hex_tx_hashes],
)
b.calculate_merkle_tree()
index = b.tx_hashes.index(tx_hash)
proof_hashes = []
current_index = index
for level in b.merkle_tree:
    if current_index % 2 == 1:
        partner = current_index - 1
    else:
        partner = current_index + 1
    proof_hashes.append(level[partner])
    current_index //= 2
proof = Proof(b.merkle_root, tx_hash, index, proof_hashes)
print(proof)
```

### Try it

#### Create a Merkle Proof for this transaction
Transaction Hash:
```
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
```

Block Hex:
```
00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000
```

Transaction Hashes:
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```


```python
# Exercise 7.1

from io import BytesIO

from block import Block, Proof
from helper import merkle_path

tx_hash = bytes.fromhex('e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208')
tx_hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]
stream = BytesIO(bytes.fromhex('00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000'))
b = Block.parse(stream)
b.tx_hashes = [bytes.fromhex(x) for x in tx_hex_hashes]

# calculate the merkle tree first
b.calculate_merkle_tree()
# get the index of the tx_hash in the list of tx_hashes (b.tx_hashes.index(tx_hash))
index = b.tx_hashes.index(tx_hash)
# initialize the proof hashes
proof_hashes = []
# initialize the current index to the index at the lowest level (index)
current_index = index
# loop through merkle tree levels
for level in b.merkle_tree:
    # if the current index is odd, the partner index is - 1
    if current_index % 2 == 1:
        partner_index = current_index - 1
    # if the current index is even, the partner index is + 1
    else:
        partner_index = current_index + 1
    # partner is at the level's partner index
    partner = level[partner_index]
    # add the partner to proof hashes
    proof_hashes.append(partner)
    # update current_index to be integer divide by 2
    current_index //= 2
# create the Proof object
proof = Proof(b.merkle_root, tx_hash, index, proof_hashes)
# print the proof
print(proof)
```

### Test Driven Exercise


```python
from block import Block 

class Block(Block):
    
    def create_merkle_proof(self, tx_hash):
        # if self.merkle_tree is empty, go and calculate the merkle tree
        if self.merkle_tree is None:
            self.calculate_merkle_tree()
        # find the index of this tx_hash
        index = self.tx_hashes.index(tx_hash)
        # initialize proof hashes
        proof_hashes = []
        # initialize the current index to be the index at the base level
        current_index = index
        # Loop over the levels in the merkle tree
        for level in self.merkle_tree:
            # Find the partner index (-1 for odd, +1 for even)
            if current_index % 2 == 1:
                partner_index = current_index - 1
            else:
                partner_index = current_index + 1
            # partner is at the level's partner index
            partner = level[partner_index]
            # add partner to proof hashes
            proof_hashes.append(partner)
            # update the current_index to be integer divide by 2
            current_index //= 2
        # Return a Proof instance Proof(root, tx_hash, index, proof_hashes)
        return Proof(self.merkle_root, tx_hash, index, proof_hashes)
```
