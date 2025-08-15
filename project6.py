import os
import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import phe  # Paillier加密库，需通过pip安装：pip install phe

# 手动定义SECP256R1曲线的阶数（NIST P-256的已知阶数）
SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class Party1:
    def __init__(self):
        # 初始化椭圆曲线（使用论文中提到的prime256v1）
        self.curve = ec.SECP256R1()
        # 生成私钥（对应论文中的k1）
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        # 使用预定义的曲线阶数（修正错误的关键）
        self.curve_order = SECP256R1_ORDER
        # 存储接收的数据
        self.received_Z = None
        self.received_pairs = None

    def set_identifiers(self, identifiers):
        """设置P1的用户标识符集合V"""
        self.identifiers = identifiers

    def round1(self):
        """执行协议第一轮：计算H(v_i)^k1并打乱发送"""
        hashed_exponentiated = []
        for identifier in self.identifiers:
            # 哈希到椭圆曲线
            hash_val = hashlib.sha256(identifier.encode()).digest()
            # 将哈希值映射到曲线上的点
            hash_int = int.from_bytes(hash_val, byteorder='big') % self.curve_order
            # 计算H(v_i)^k1
            exponentiated = pow(hash_int, self.private_key.private_numbers().private_value, self.curve_order)
            hashed_exponentiated.append(exponentiated)

        # 打乱顺序
        random.shuffle(hashed_exponentiated)
        return hashed_exponentiated

    def process_round2_data(self, Z, pairs):
        """处理从P2收到的第二轮数据"""
        self.received_Z = set(Z)
        self.received_pairs = pairs

    def round3(self, paillier_pub_key):
        """执行协议第三轮：计算交集并求同态和"""
        ciphertexts_to_sum = []

        for g_j, ct_j in self.received_pairs:
            # 计算H(w_j)^(k1*k2)
            g_j_k1 = pow(g_j, self.private_key.private_numbers().private_value, self.curve_order)

            # 检查是否在交集内
            if g_j_k1 in self.received_Z:
                ciphertexts_to_sum.append(ct_j)

        # 计算交集大小
        intersection_size = len(ciphertexts_to_sum)

        # 同态求和
        if ciphertexts_to_sum:
            sum_ct = ciphertexts_to_sum[0]
            for ct in ciphertexts_to_sum[1:]:
                sum_ct += ct  # 利用Paillier的加法同态性
        else:
            sum_ct = paillier_pub_key.encrypt(0)

        # 随机化密文
        sum_ct = sum_ct + paillier_pub_key.encrypt(0)

        return intersection_size, sum_ct


class Party2:
    def __init__(self):
        # 初始化椭圆曲线
        self.curve = ec.SECP256R1()
        # 生成私钥（对应论文中的k2）
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        # 使用预定义的曲线阶数
        self.curve_order = SECP256R1_ORDER
        # 生成Paillier密钥对
        self.paillier_pub_key, self.paillier_priv_key = phe.generate_paillier_keypair()

    def set_identifiers_with_values(self, identifiers_with_values):
        """设置P2的用户标识符与值的集合W"""
        self.identifiers_with_values = identifiers_with_values

    def get_paillier_public_key(self):
        """获取Paillier公钥，提供给P1"""
        return self.paillier_pub_key

    def round2(self, data_from_p1):
        """执行协议第二轮：处理P1的数据并生成发送给P1的数据"""
        # 计算Z = {H(v_i)^(k1*k2)}
        Z = []
        for item in data_from_p1:
            z = pow(item, self.private_key.private_numbers().private_value, self.curve_order)
            Z.append(z)
        # 打乱Z的顺序
        random.shuffle(Z)

        # 计算{(H(w_j)^k2, AEnc(t_j))}
        pairs = []
        for identifier, value in self.identifiers_with_values:
            # 哈希标识符
            hash_val = hashlib.sha256(identifier.encode()).digest()
            hash_int = int.from_bytes(hash_val, byteorder='big') % self.curve_order
            # 计算H(w_j)^k2
            g_j = pow(hash_int, self.private_key.private_numbers().private_value, self.curve_order)
            # 加密值
            ct_j = self.paillier_pub_key.encrypt(value)
            pairs.append((g_j, ct_j))

        # 打乱pairs的顺序
        random.shuffle(pairs)

        return Z, pairs

    def process_round3_data(self, intersection_size, sum_ct):
        """处理从P1收到的第三轮数据，解密得到结果"""
        # 解密交集和
        intersection_sum = self.paillier_priv_key.decrypt(sum_ct)
        return intersection_size, intersection_sum


# 协议执行示例
def run_protocol():
    # 示例数据
    p1_identifiers = ["user1", "user2", "user3", "user4", "user5"]
    p2_identifiers_with_values = [
        ("user3", 100), ("user5", 200), ("user6", 300),
        ("user7", 400), ("user2", 500)
    ]

    # 初始化双方
    p1 = Party1()
    p2 = Party2()

    # 设置数据
    p1.set_identifiers(p1_identifiers)
    p2.set_identifiers_with_values(p2_identifiers_with_values)

    # 交换Paillier公钥
    paillier_pub_key = p2.get_paillier_public_key()

    # 第一轮：P1 -> P2
    round1_data = p1.round1()

    # 第二轮：P2 -> P1
    Z, pairs = p2.round2(round1_data)
    p1.process_round2_data(Z, pairs)

    # 第三轮：P1 -> P2
    intersection_size_p1, sum_ct = p1.round3(paillier_pub_key)
    intersection_size_p2, intersection_sum = p2.process_round3_data(intersection_size_p1, sum_ct)

    # 输出结果
    print(f"P1计算的交集大小: {intersection_size_p1}")
    print(f"P2计算的交集大小: {intersection_size_p2}")
    print(f"P2计算的交集和: {intersection_sum}")
    print("\n预期结果（明文计算）：")
    p1_set = set(p1_identifiers)
    intersection = [v for (k, v) in p2_identifiers_with_values if k in p1_set]
    print(f"实际交集大小: {len(intersection)}")
    print(f"实际交集和: {sum(intersection)}")


if __name__ == "__main__":
    run_protocol()
