import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from aes_keywrap import aes_wrap_key, aes_unwrap_key


class CSE:

    def __init__(self, **kwargs):

        self.master_key = None

        if 'master_key' in kwargs:
            self.master_key = kwargs['master_key']

    def decrypt_object(self, data, metadata, **kwargs):

        if 'master_key' in kwargs:
            master_key = kwargs['master_key']
        elif self.master_key is not None:
            master_key = self.master_key
        else:
            raise TypeError('required keyword argument master_key is missing')

        if 'x-amz-wrap-alg' not in metadata:
            raise KeyError('Metadata key x-amz-wrap-alg is missing')
        wrap_alg = metadata['x-amz-wrap-alg']

        if 'x-amz-cek-alg' not in metadata:
            raise KeyError('Metadata key x-amz-cek-alg is missing')
        cek_alg = metadata['x-amz-cek-alg']

        if 'x-amz-key-v2' not in metadata:
            raise KeyError('Metadata key x-amz-key-v2 is missing')
        envelope_key = metadata['x-amz-key-v2']

        if 'x-amz-iv' not in metadata:
            raise KeyError('Metadata key x-amz-iv is missing')
        envelope_iv = metadata['x-amz-iv']

        envelope_key = base64.b64decode(envelope_key)
        envelope_iv = base64.b64decode(envelope_iv)

        if wrap_alg.lower() != 'AESWrap'.lower():
            raise NotImplementedError('Key wrapping algorithm {} is not supported'.format(wrap_alg))

        envelope_key = aes_unwrap_key(master_key, envelope_key)

        if cek_alg.lower() != 'AES/GCM/NoPadding'.lower():
            raise NotImplementedError('Content encryption algorithm {} is not supported'.format(cek_alg))

        decryptor = AES.new(envelope_key, AES.MODE_GCM, nonce=envelope_iv)

        return decryptor.decrypt(data)

    def encrypt_object(self, data, **kwargs):

        if 'master_key' in kwargs:
            master_key = kwargs['master_key']
        elif self.master_key is not None:
            master_key = self.master_key
        else:
            raise TypeError('required keyword argument master_key is missing')

        envelope_key = get_random_bytes(32)
        envelope_iv = get_random_bytes(16)
        encryptor = AES.new(envelope_key, AES.MODE_GCM, nonce=envelope_iv)

        envelope_key = aes_wrap_key(master_key, envelope_key)

        metadata = {
            'x-amz-key-v2': base64.b64encode(envelope_key).decode('utf-8'),
            'x-amz-iv': base64.b64encode(envelope_iv).decode('utf-8'),
            'x-amz-cek-alg': 'AES/GCM/NoPadding',
            'x-amz-wrap-alg': 'AESWrap',
            'x-amz-matdesc': '{}',
            'x-amz-unencrypted-content-length': str(len(data)),
        }

        return encryptor.encrypt(data), metadata
