import os
import argparse


filenameList=['noodles','tdseq',"httpd","cgi","dsd","upnp",'boa',"maintain","NVMS9000","ipeye_p2p","ConfigAdapter"]
def is_elf(file_path):#G:\\bindiff_project\\firm\\_R6700-V1.0.2.16_10.0.57\\squashfs-root\\data

    try:
        with open(file_path,"rb")as fd:
            content=fd.read(4)[1:]
#         print(content,file_path)
    except:
        print("file {} read error".format(file_path))
        content=""
    flag=False
    for i in  filenameList:
        if i in file_path.lower():
            flag=True
#     print(flag)
    return (content==b"ELF") and flag==True
def GetElfs(path):
    elf_file_list=set()
    for fpathe,dirs,fs in os.walk(path):
        for f in fs:
            if is_elf(os.path.join(fpathe, f)):
                print("is elf",is_elf)
                elf_file_list.add(os.path.join(fpathe, f))
                yield os.path.join(fpathe, f)

def init():
    parser = argparse.ArgumentParser(description='Index executables.')
    parser.add_argument('--input_dir', type=str,default=input,
                            help="need input dir --input {}".format(input))
    args = vars(parser.parse_args())
    return args

def clean():
    os.system("rm -rf  ./out/input/*")
    os.system("rm -rf ./out/report/*")
    os.system("rm -rf ./out/indexed/*")


project_path=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# project_path
# print(project_path)


if __name__=="__main__":
    args=init()
    clean()
    print("dir",args["input_dir"])
#     for filename in GetElfs(args["input_dir"]):
    filename="/Users/guosiyu/Desktop/aiwencode/loudong_liyong/tvt/exttactor/squashfs-root/mnt/mtd/NVMS9000"
    os.system("cp {} {}/out/input/".format(filename,project_path))
    CMD="""analyzeHeadless  {}/out/output aa -scriptPath \
    {}/src -postScript Comfu_function.java -import  \
    {}/out/input/{}  -overwrite""".format(project_path,project_path,project_path,os.path.basename(filename))
    print(CMD)
    os.system(CMD)