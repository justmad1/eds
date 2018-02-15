import rsa
import hashlib
import os

path = "/Users/dima/Desktop/package/"
filename = path + "message.txt"


def main():
    while True:
        choise = input("""
[1] - Create package
[2] - Check digital signature
 >> """)
        if choise is '1':
            message = input("[message] >> ")
            create_package(message)

        elif choise is '2':
            print(check_signature())
        else:
            break


def check_signature():
    try:
        file = open(path + 'message.txt')
        message = file.read()
        file.close()
        file = open(path + 'signature', 'rb')
        signature = file.read()
        file.close()
        with open(path + "key", "r") as f:
            n = int(f.readline())
            d = int(f.readline())
            p = int(f.readline())
            q = int(f.readline())
            exp1 = int(f.readline())
            exp2 = int(f.readline())
            coef = int(f.readline())
        file.close()
        hash = get_hash(message)
        temp_hash = rsa.decrypt(signature, rsa.PrivateKey(n, 65537, d, p, q, exp1, exp2, coef)).decode("utf8")
        if temp_hash == hash:
            return True
        else:
            return False
    except Exception as e:
        print('Package not exist or damaged!')
        return None


def create_package(message):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass
    (pub, priv) = rsa.newkeys(512)
    if create_file(message, pub) and create_signature(message, pub) and create_key_file(priv):
        print("\nPackage created at", path)


def create_file(message, pub):
    try:
        with open(filename, "w") as f:
            f.write(message)
            return True
    except Exception:
        print("Error in creating file!")
        return False


def create_key_file(priv):
    try:
        with open(path + "key", "w") as f:
            f.write(str(priv.n) + "\n")
            f.write(str(priv.d) + "\n")
            f.write(str(priv.p) + "\n")
            f.write(str(priv.q) + "\n")
            f.write(str(priv.exp1) + "\n")
            f.write(str(priv.exp2) + "\n")
            f.write(str(priv.coef) + "\n")
        return True
    except Exception:
        print("Error in creating key file!")
        return False


def create_signature(message, pub):
    try:
        h = get_hash(message).encode("utf8")
        signature = rsa.encrypt(h, pub)
        with open(path + "signature", "wb") as f:
            f.write(signature)
        return True
    except Exception:
        print("Error in creating signature!")
        return False


def get_hash(message):
    message_utf8 = message.encode("utf8")
    h = hashlib.md5(message_utf8)
    return h.hexdigest()


# -------------------------------------------------------------------
def test():
    (pub, priv) = rsa.newkeys(512)
    crypto = rsa.encrypt("hello".encode("utf8"), priv)
    with open("/Users/dima/Desktop/" + "k.txt", "w") as f:
        f.write(str(priv.n) + "\n")
        f.write(str(priv.d) + "\n")
        f.write(str(priv.p) + "\n")
        f.write(str(priv.q) + "\n")
        f.write(str(priv.exp1) + "\n")
        f.write(str(priv.exp2) + "\n")
        f.write(str(priv.coef) + "\n")

    with open("/Users/dima/Desktop/" + "k.txt", "r") as f:
        n = int(f.readline())
        d = int(f.readline())
        p = int(f.readline())
        q = int(f.readline())
        exp1 = int(f.readline())
        exp2 = int(f.readline())
        coef = int(f.readline())

    decrypt = rsa.decrypt(crypto, rsa.PrivateKey(n, 65537, d, p, q, exp1, exp2, coef))
    print(decrypt)


def test2():
    file = open(path + 'message.txt')
    message = file.read()
    file.close()
    file = open(path + 'signature', 'rb')
    signature = file.read()
    file.close()
    with open(path + "key", "r") as f:
        n = int(f.readline())
        d = int(f.readline())
        p = int(f.readline())
        q = int(f.readline())
        exp1 = int(f.readline())
        exp2 = int(f.readline())
        coef = int(f.readline())
    file.close()
    hash = get_hash(message)
    temp_hash = rsa.decrypt(signature, rsa.PrivateKey(n, 65537, d, p, q, exp1, exp2, coef))
    if temp_hash == hash:
        return True
# -------------------------------------------------------------------


if __name__ == "__main__":
    main()
