#获取关键变量的切片序列

KeyStatement，目前定为所有的函数调用。
给定二进制文件，用ghidra进行反编译，基于伪代码的token进行跨函数的变量追踪。



# CallParamSlience
从反编译结果追踪问题：
- 一个变量可能在多条指令被赋值，可能多条赋值都有用，目前的策略为追踪所有的赋值。在pcode层面由于SSA属性不存在该问题。



目前实现基于伪代码的参数依赖分析，


# 安装

使用

- ghidra_10.1.4
- java  11.0.12

把lib目录中三个文件拷贝到 ghidra_10.1.4_PUBLIC/Extensions/Ghidra/Skeleton/lib
- jackson-annotations-2.13.3
- jackson-core-2.13.2
- jackson-databind-2.13.2.2

运行示例
```bash
python3 src/start.py --input_dir ./input/_DIR-600_Bx_FW218WWb01.bin.extracted
```
输出目录

- out/indexed  存放追踪到的代码链，用于自动化分析
- out/input 为分析的二进制文件备份，仅从固件中分析部分二进制文件，在src/start.py文件中指定。
- out/report   存放每个文件进行漏洞检测的结果




# 说明
- src/Check/CheckStackOverflow 检测缓冲区溢出，目前方案为检测危险函数中参数来源是否为外部输入
- src/Check/CmdInject  检测命令注入，同样为检测参数来源是否为外部输入

根据检测参数来源的确定程度，目前分为三个level

- 1  参数和一些字符串相关
- 2  参数和特定字符串相关，或进行了一些字符串切割、比较等