from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode


class AESImageCipher:
    # Image
    url = None  # Ruta completa de la imagen
    image = None  # Objeto de la imagen
    image_name = None  # nombre de imagen sin extensiones
    path = None  # Ruta de la carpeta de la imagen
    image_size = None  # Resolucion de la iamgen
    image_ext = None

    # Cipher
    key = None
    iv = None
    mode = AES.MODE_ECB

    def __init__(self):
        pass

    def setImagePath(self, ruta: str):
        self.url = ruta
        aux = ruta.split("/")
        name = aux[-1].split(".")
        self.image_ext = name[-1]
        self.image_name = name[0]
        self.path = self.url.replace(aux[-1], "")

    def setKey(self, key: bytes):
        self.key = pad(key, 16)

    def setIv(self, iv: bytes):
        self.iv = pad(iv, 16)

    def setMode(self, modo: str):
        if(modo == 'ECB'):
            self.mode = AES.MODE_ECB
        elif(modo == 'CBC'):
            self.mode = AES.MODE_CBC
        elif(modo == 'CFB'):
            self.mode = AES.MODE_CFB
        elif(modo == 'OFB'):
            self.mode = AES.MODE_OFB
        else:
            print("Mode not recognized")

    def getMode(self):
        if(self.mode == AES.MODE_ECB):
            return "ECB"
        elif(self.mode == AES.MODE_CBC):
            return "CBC"
        elif(self.mode == AES.MODE_CFB):
            return "CFB"
        elif(self.mode == AES.MODE_OFB):
            return "OFB"
        else:
            return None

    def encrypt(self):
        if(self.url != None and self.key != None):
            print("Cifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            # print(len(self.image))
            self.image_size = img.size
            #print(self.key, self.iv)
            new_url = self.path + self.image_name + "_e" + self.getMode() + "." + self.image_ext

            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            ct_bytes = cipher.encrypt(
                pad(
                    self.image.tobytes(),
                    AES.block_size,
                )
            )
            img_data = np.frombuffer(ct_bytes)
            # print(len(img_data))

            image_nva = Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            )
            image_nva.save(
                new_url
            )
            print("Cifrado")

    def decrypt(self):
        if(self.url != None and self.key != None):
            print("Decifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            self.image_size = img.size

            new_url = self.path + self.image_name + "_d" + self.getMode() + "." + self.image_ext
            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            aux = self.image.tobytes()
            # pt = unpad(
            #     cipher.decrypt(
            #         self.image.tobytes()
            #     ),
            #     AES.block_size
            # )
            pt = cipher.decrypt(
                aux
            )

            #print("PT:  ", len(pt))

            img_data = np.frombuffer(pt)

            Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            ).save(
                new_url
            )
            # print("Decifrado")


if __name__ == "__main__":

    key = b'Estos son 16 bts'
    iv = b'0123456789ABCDEF'
    cipher = AESImageCipher()
    cipher.setImagePath('images\Imagen1.bmp')
    cipher.setKey(key)
    cipher.setIv(iv)
    cipher.setMode("CBC")
    cipher.encrypt()

    cipher2 = AESImageCipher()
    cipher2.setImagePath('images\Imagen1_eCBC.bmp')
    cipher2.setKey(key)
    cipher2.setIv(iv)
    cipher2.setMode("CBC")
    cipher2.decrypt()

    key = b'Estos son 16 bts'
    iv = b'0123456789ABCDEF'
    cipher = AESImageCipher()
    cipher.setImagePath('images\Imagen2.bmp')
    cipher.setKey(key)
    cipher.setIv(iv)
    cipher.setMode("CBC")
    cipher.encrypt()

    cipher2 = AESImageCipher()
    cipher2.setImagePath('images\Imagen2_eCBC.bmp')
    cipher2.setKey(key)
    cipher2.setIv(iv)
    cipher2.setMode("CBC")
    cipher2.decrypt()

    # initial_image = Image.open('images\koala.jpg')
    # size_image = initial_image.size
    # data_image = np.array(initial_image)

    # # print(len(data_image))

    # key = b'Estos son 16 bts'
    # iv = b'0123456789ABCDEF'

    # cipher = AES.new(key, AES.MODE_CBC, iv)

    # ct_bytes = cipher.encrypt(pad(data_image.tobytes(), AES.block_size))
    # print("IMG: ", len(data_image.tobytes()))
    # print("ENC: ", len(ct_bytes))
    # img_data = np.frombuffer(ct_bytes)
    # Image.frombuffer("RGB", size_image, img_data).save(
    #     'images\koala_encrypted.png')

    # # ct = b64encode(ct_bytes).decode('utf-8')
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # print("ENC: ", len(ct_bytes))
    # pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    # print("PT:  ", len(pt))
    # img_data = np.frombuffer(pt)
    # Image.frombuffer("RGB", size_image, img_data).save(
    #     'images\koala_decrypted.png')
