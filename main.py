from utils import *


def prove(key, msg):
    print('key:       {:x}'.format(key))
    print('message:   {:x}'.format(msg))
    cipher_text = encrypt(msg, key)
    print('encrypted: {:x}'.format(cipher_text))
    plain_text = encrypt(cipher_text, key)
    print('decrypted: {:x}'.format(plain_text))


def read_message_from_fie():
    text_file_name = input('Enter file name: ') + '.bin'

    with open(text_file_name, 'rb') as binary_read:
        data = binary_read.read()

        data = int(data, 2)

    return data


def show_menu():
    pass


if __name__ == '__main__':
    msg = read_message_from_fie()
    KEY = 0x133457799BBCDFF1

    prove(KEY, msg)
