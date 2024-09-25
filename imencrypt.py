from tkinter import *
from tkinter.filedialog import *
import tkinter.messagebox
import os
from PIL import Image
import PIL
import math
from Crypto.Cipher import AES
import hashlib
import binascii
from Crypto import Random
import base64

global password # make pass global var将密码设置为全局变量

def construct_enc_image(ciphertext, encim_name, width, height):
    # hexlify the ciphertext    加密密文
    asciicipher = binascii.hexlify(ciphertext.encode())
#     print('1:'+str(asciicipher))
    dec_asciiciphertxt=[]
    for char in asciicipher:
        dec_asciiciphertxt.append(char)
    # construct encrypted image使用replace函数将ascii密码字符替换为数字
#     print('2:'+str(dec_asciiciphertxt))
    step = 3
    relength = width*height
    while (len(dec_asciiciphertxt) % 3 != 0):
        dec_asciiciphertxt.append(101)
    encimagetwo=[(dec_asciiciphertxt[int(i)],dec_asciiciphertxt[int(i+1)],dec_asciiciphertxt[int(i+2)]) for i in range(0, len(dec_asciiciphertxt), step)]
    
    if len(encimagetwo)%width!=0:
        remainder = len(encimagetwo)%width
        for i in range(abs(width-remainder)):
            encimagetwo.append((0,0,0))
#     width, height= factorize(len(encimagetwo))
#     print(encimagetwo)
    encpic_height = len(encimagetwo)//width
    encim = Image.new("RGB", (int(width),int(encpic_height)))
    encim.putdata(encimagetwo)
    # encim_name = imagename + "_crypt.png"
    encim.save(encim_name)

def image_enc(imagename):
    # hexlify the ciphertext    加密密文
    im = Image.open(imagename)  # open target image打开目标图片
    pix = im.load()
    width = im.size[0]
    height = im.size[1]
    enctext = []
    enctextstr = ''
    for y in range(0,height):
        #print("Row: %d") %y  # print row number打印行号
        if y == height -1:
            for x in range(0,width):
                if pix[x,y] != (0,0,0):
                    enctext.append(pix[x,y])
        else:
            for x in range(0,width):
            #print pix[x,y]  # print each pixel RGB tuple打印每个像素的RGB元组
                enctext.append(pix[x,y])

    for i in range(0,len(enctext)):
        # enctext[i].pop()
        if i == len(enctext)-1:
            for j in range(0,3):
                # temp = chr(int(enctext[i][j]))
                temp = enctext[i][j]
                if temp != 101:
                    enctextstr= enctextstr + chr(int(temp))
        else:
            for j in range(0,3):
                # temp = chr(int(enctext[i][j]))
                temp = enctext[i][j]
                enctextstr= enctextstr + chr(int(temp))
#     print('3:'+enctextstr)
    ciphertext = binascii.unhexlify(enctextstr.encode())
#     print('3:'+str(ciphertext))
    return ciphertext


# encryption method加密方法
# -----------------
def encrypt(imagename,password):
    # initialize variables初始化变量
    plaintext = list()
    plaintextstr = ""
    
    # load the image加载图片
    im = Image.open(imagename)  # open target image打开目标图片
    pix = im.load()
    
    #print im.size   # print size of image (width,height)#print im.size # 打印图片大小（宽度，高度）
    width = im.size[0]
    height = im.size[1]
    
    # break up the image into a list, each with pixel values and then append to a string将图片拆分为一个列表，每个列表包含像素值，然后追加到字符串中
    for y in range(0,height):
        #print("Row: %d") %y  # print row number打印行号
        for x in range(0,width):
            #print pix[x,y]  # print each pixel RGB tuple打印每个像素的RGB元组
            plaintext.append(pix[x,y])

    for i in range(0,len(plaintext)):
        for j in range(0,3):
            plaintextstr = plaintextstr + "%d" %(int(plaintext[i][j])+100)
    
    # length save for encrypted image reconstruction加密图像重建的长度保存
    relength = len(plaintext)
    
    # append dimensions of image for reconstruction after decryption为解密后的重建添加图像尺寸
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"
    
    # make sure that plantextstr length is a multiple of 16 for AES.  if not, append "n".  not safe in theory
    # and i should probably replace this with an initialization vector IV = 16 * '\x00' at some point.  In practice
    # this IV buffer should be random.
    #对于AES，请确保plantextstr长度是16的倍数。如果没有，则附加“n”。理论上不安全
    # 我可能应该在某个时候用初始化向量IV = 16 *‘\ x00‘来替换它。在实践中
    # 这个静脉注射缓冲液应该是随机的。
    while (len(plaintextstr) % 16 != 0):
        plaintextstr = plaintextstr + "n"
    
    
    # print(plaintextstr)
    # encrypt plaintext加密明文
    iv = Random.new().read(AES.block_size)
    obj = AES.new(password, AES.MODE_CBC, iv)
    ciphertext = base64.b64encode(iv + obj.encrypt(plaintextstr)).decode('utf-8')
    # print(ciphertext)
    imghead = imagename.partition('.')
    enc_picname = imghead[0] + "_crypt.png"
    construct_enc_image(ciphertext, enc_picname, width, height)
    enc_success(enc_picname)


def decrypt(cipherpicname,password):
    
    ciphertext = image_enc(cipherpicname)
    
    # print(ciphertext)
    enc = base64.b64decode(ciphertext)
    iv = enc[:AES.block_size]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    # decrypt ciphertext with password用密码解密密文
    # obj2 = AES.new(password, AES.MODE_CBC, 'This is an IV456')
    # decrypted = obj2.decrypt(ciphertext)
    decrypted = cipher.decrypt(enc[AES.block_size:]).decode('utf-8')
    
    # parse the decrypted text back into integer string将解密的文本解析回整数字符串
    # print(decrypted)
    decrypted = decrypted.replace('n', '')
    
    # extract dimensions of images提取图像的尺寸
    # print(decrypted)
    newwidth = decrypted.split("w")[1]
    newheight = decrypted.split("h")[1]
    
    # replace height and width with emptyspace in decrypted plaintext在解密的明文中用空格替换高度和宽度
    heightr = "h" + str(newheight) + "h"
    widthr = "w" + str(newwidth) + "w"
    decrypted = decrypted.replace(heightr,"")
    decrypted = decrypted.replace(widthr,"")

    # reconstruct the list of RGB tuples from the decrypted plaintext从解密的明文中重建RGB元组列表
    step = 3
    finaltextone=[decrypted[i:i+step] for i in range(0, len(decrypted), step)]
    finaltexttwo=[(int(finaltextone[int(i)])-100,int(finaltextone[int(i+1)])-100,int(finaltextone[int(i+2)])-100) for i in range(0, len(finaltextone), step)]    

    # reconstruct image from list of pixel RGB tuples从像素RGB元组列表重建图像
    newim = Image.new("RGB", (int(newwidth), int(newheight)))
    newim.putdata(finaltexttwo)

    pichead  = cipherpicname.partition('.')
    newim_name = pichead[0]+ "_decrypt.png"
    newim.save(newim_name)
    newim.show()
    
# ---------------------
# GUI stuff starts hereGUI的东西从这里开始
# ---------------------

# empty password alert 空密码警报
def pass_alert():
   tkinter.messagebox.showinfo("Password Alert","Please enter a password.")
   
def enc_success(imagename):
   tkinter.messagebox.showinfo("Success","Encrypted Image: " + imagename)
   
# image encrypt button event图像加密按钮事件
def image_open():
    # useless for now, may need later现在没用，以后可能需要
    global file_path_e
    
    # check to see if password entry is null.  if yes, alert检查密码条目是否为空。如果是，则发出警报
    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass.encode()).digest()
        filename = askopenfilename()
        file_path_e = os.path.dirname(filename)
        # encrypt the image加密图像
        encrypt(filename,password)
    
# image decrypt button event图像解密按钮事件
def cipher_open():
    # useless for now, may need later现在没用，以后可能需要
    global file_path_d
        
    # check to see if password entry is null.  if yes, alert检查密码条目是否为空。如果是，则发出警报
    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:    
        password = hashlib.sha256(dec_pass.encode()).digest()
        filename = askopenfilename()
        file_path_d = os.path.dirname(filename)
        # decrypt the ciphertext解密密文
        decrypt(filename,password)

# main gui app starts here主gui应用程序从这里开始
class App:
  def __init__(self, master):
    # make passg global to use in functions使passg在函数中全局使用
    global passg
    # setup frontend titles etc blah blah设置前端标题等等等等
    title = "Image Encryption"
    msgtitle = Message(master, text =title)
    msgtitle.config(font=('helvetica', 17, 'bold'), width=200)
    msgauthor = Message(master, text=author)
    msgauthor.config(font=('helvetica',10), width=200)

    # draw canvas绘制画布
    canvas_width = 200
    canvas_height = 50
    w = Canvas(master, 
           width=canvas_width,
           height=canvas_height)

    # pack the GUI, this is basic, we shold use a grid system打包GUI，这是基本的，我们应该使用网格系统
    msgtitle.pack()
    msgauthor.pack()
    w.pack()
    
    # password field here above buttons按钮上方的密码栏
    passlabel = Label(master, text="Enter Encrypt/Decrypt Password:")
    passlabel.pack()
    passg = Entry(master, show="*", width=20)
    passg.pack()

    # add both encrypt/decrypt buttons here which trigger file browsers在这里添加触发文件浏览器的加密/解密按钮
    self.encrypt = Button(master, 
                         text="Encrypt", fg="black", 
                         command=image_open, width=25,height=5)
    self.encrypt.pack(side=LEFT)
    self.decrypt = Button(master,
                         text="Decrypt", fg="black",
                         command=cipher_open, width=25,height=5)
    self.decrypt.pack(side=RIGHT)



root = Tk()
root.wm_title("Image Encryption")
app = App(root)
root.mainloop()


