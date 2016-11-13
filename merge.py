import os
import shutil

dic_counter={0:0};

def add_counter_from_file(filename):
    fobj = open(filename,'r')
    try:
        for eachline in fobj:
            if eachline.find(":") != -1:
                TempTruple=eachline.partition(":")
                k = int(TempTruple[0])
                v = int(TempTruple[2])
                if dic_counter.has_key(k):
                    dic_counter[k] += v;
                else:
                    dic_counter[k] = v;
    finally:
        fobj.close()

def out_counter_to_file(filename):
    fobj = open(filename,'w')
    dic_counter_local={};
    try:
        dic_counter_local = sorted(dic_counter.iteritems(), key=lambda d:d[0]);
        print dic_counter_local;
        for k,v in dic_counter.items():
            fobj.write(str(k)+":"+str(v)+"\n");
    finally:
        fobj.close()


def merge_counter(path,filenamefilter):
    try:
        for root,dirs,files in os.walk(path):
            print files;
            for fn in files:
                if fn.find(filenamefilter) != -1:
                    add_counter_from_file(fn);
        out_counter_to_file(path+"_"+filenamefilter+"_merge.txt")
    finally:
        print "OK";

def diff_counter(filename1,filename2):
    fobj1 = open(filename1,'r')
    fobj2 = open(filename2,'r')    
    try:
        for eachline in fobj1:
            if eachline.find(":") != -1:
                TempTruple=eachline.partition(":")
                k = int(TempTruple[0])
                v = int(TempTruple[2])
                dic_counter[k] = v;
        for eachline in fobj2:
            if eachline.find(":") != -1:
                TempTruple=eachline.partition(":")
                k = int(TempTruple[0])
                v = int(TempTruple[2])               
                if dic_counter.has_key(k):
                    dic_counter[k] -= v;
                else:
                    dic_counter[k] = 0-v;

        out_counter_to_file(filename1+"_"+filename2+"_diff.txt")     
    finally:
        fobj1.close()
        fobj2.close()




        
