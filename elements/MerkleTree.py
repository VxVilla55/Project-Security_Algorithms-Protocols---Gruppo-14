import hashlib

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

class MerkleTree:
    tree: list[list[str]]
    root: str
    
    def __init__(self, data_list: list[str]):
        """Build a Merkle tree. Returns (root_hash, tree) where tree[0] = leaves."""
        if not data_list:
            raise ValueError("data_list must not be empty")

        tree = [[sha256(d) for d in data_list]]

        while len(tree[-1]) > 1:
            level = tree[-1]
            if len(level) % 2 == 1:
                level = level + [level[-1]]  # duplicate last if odd
            
            # note: each parent is the hash of the concatenation of its two children
            # the order here matters!! (if we swap them we have a completely different result)
            tree.append([
                sha256(level[i] + level[i + 1])
                for i in range(0, len(level), 2)
            ])

        self.tree = tree
        self.root = self.tree[-1][0]


    def generate_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        """Return inclusion proof for leaf at leaf_index as [(position, hash), ...]."""
        proof = []
        index = leaf_index

        # we skip the root here
        for level in self.tree[:-1]:
            # we duplicate the last node if level has an odd count
            # (usually used in Bitcoin for instance)
            if len(level) % 2 == 1:
                level = level + [level[-1]]

            # this is also called XOR sibling trick
            # XOR with 1 flips the last bit: if index is even (left child),
            # sibling index becomes index + 1 (right child), and vice versa
            sibling_index = index ^ 1
            position = "right" if sibling_index > index else "left"
            # right means the sibling is to our right, so when reconstruting
            # the parent hash we place our cuurrent hash on the LEFT: hash(ours + sibling)
            proof.append((position, level[sibling_index]))
            index //= 2

        return proof


    def verify_proof(self, data: str, proof: list[tuple[str, str]], root: str) -> bool:
        """Verify an inclusion proof against the given root."""
        current = sha256(data)  # start from the leaf

        for position, sibling in proof:
            # reconstruct the parent by hashing this node together with its sibling
            if position == "right":
                current = sha256(current + sibling)
            else:
                current = sha256(sibling + current)

        # this is true if the reconstructed hash mathces the trusted root, i.e., the proof is valid
        return current == root


def print_tree(tree: list[list[str]], data_list: list[str]) -> None:
    print(f"\nMerkle Tree ({len(data_list)} leaves, depth {len(tree)}):")
    labels = ["Leaves"] + [f"Level {i}" for i in range(1, len(tree) - 1)] + ["Root"]
    for label, level in zip(labels, tree):
        hashes = "  ".join(h[:8] + "..." for h in level)
        print(f"  {label:<10} {hashes}")
    print()


def print_proof(proof: list[tuple[str, str]], leaf_index: int) -> None:
    print(f"Proof for leaf[{leaf_index}] ({len(proof)} steps):")
    for i, (position, h) in enumerate(proof):
        print(f"  step {i + 1}: {position:5}  {h[:16]}...")
    print()


if __name__ == "__main__":
    data_list = ["msg_1", "msg_2", "msg_3", "msg_4", "msg_5", "msg_6", "msg_7", "msg_8"]

    tree = MerkleTree(data_list)
    print_tree(tree.tree, data_list)

    leaf_index = 5
    proof = tree.generate_proof(leaf_index)
    print_proof(proof, leaf_index)

    valid = tree.verify_proof(data_list[leaf_index], proof, tree.root)
    print(f"Verification: {'OK' if valid else 'FAILED'}")

    tampered = tree.verify_proof("msg_TAMPERED", proof, tree.root)
    # we expect here FAILED because proof is generated for "msg_6"
    # while we are giving "msg_TAMPERED"
    print(f"Tamper check: {'OK' if tampered else 'FAILED (expected)'}")