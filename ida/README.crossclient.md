# 跨客户端导入

`ffxiv_crossclient.py` 在 IDA 外读取参考客户端、目标客户端、`data.yml` 和 `ffxiv_structs.yml`，生成目标客户端的命名数据。原有脚本与原有数据文件均不需要修改。

需要 Python 3.10 或更高版本，以及 `pefile`、`capstone`、`PyYAML`。IDA 中仍然需要上游命名、EXD 与结构导入脚本原本使用的依赖和名称配置。

## 生成国服数据

在当前 `ida` 目录执行：

```powershell
$sourceClient = 'E:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\clients\7.57hf1\ffxiv_dx11.exe'
$targetClient = 'E:\Program Files (x86)\上海数龙科技有限公司\clients\7.57\ffxiv_dx11.exe'

python -X utf8 -B .\ffxiv_crossclient.py --source $sourceClient --target $targetClient --output .\data.cn.generated.yml --mapping .\crossclient.cn.generated.json --report .\crossclient.cn.report.json
```

参考程序必须与输入的 `data.yml` 对应。`--data` 和 `--structs` 可以指定其他输入文件。输出路径不能与输入路径相同。

匹配过程利用去除地址差异后的函数内容、已匹配函数的引用关系、唯一函数前缀、虚表槽位及唯一常量数据建立地址对应关系。C# 原生声明中的特征码分别在参考程序与目标程序中进行唯一性解析，普通函数还需要通过可执行区域和函数入口检查。

同名声明不会直接覆盖地址映射。补充缺失地址前，必须确认参考端特征码确实指向原地址表中的对应函数。二进制匹配与双端特征码定位发生分歧时，该地址和有关原生声明会被隔离，不能凭借名称或任意一侧的结果继续导入。

映射文件按两个程序的 SHA-256 校验。再次执行相同命令会复用函数映射和双端原生声明解析结果；输入命名数据或结构数据发生变化时，只更新相应部分。首次生成过程中会分阶段保存缓存，中断后可以重新执行同一命令继续处理。更换客户端程序时，应为该程序组合选择新的映射文件。

生成文件中的未解析地址会被省略。报告分别列出地址迁移未解析项、原生声明未解析项、地址对应冲突数量与双端签名定位分歧。冲突项同时计入未解析地址，不能将两者相加计算遗漏数量。不能将生成结果当成完整迁移成功的保证，应查看报告中的具体条目。

## 在 IDA 中导入

打开目标客户端对应的数据库，运行 `ffxiv_crossclient_ida.py`，选择生成的 `data.cn.generated.yml`。入口核对数据库输入程序的 SHA-256，并根据数据库当前映像基址重定位。

入口依次调用原有命名与结构导入逻辑；数据库尚未具有 EXD 基础类型时，才执行原有 EXD 步骤。游戏数据路径的要求与原有 FFCS 导入流程相同。结构导入建议选择 SrcLang。

生成数据只在本次脚本加载的内存命名空间中提供，不会替换磁盘上的 `data.yml` 或 `ffxiv_structs.yml`。普通函数与静态成员类型使用已经离线验证的地址，虚函数按当前虚表槽位应用类型。入口同时处理上游类命名器与虚表读取逻辑的基址修正，避免重定位被重复应用。

独立入口还在加载时修正原有函数指针字段的类型标记，以及 SrcLang 声明中的参数拼接和分号，磁盘源文件保持原样。

国际服也可使用同一个入口：将生成命令中的 `--target` 指向参考程序，并为它指定另一组输出文件。同一程序之间直接使用地址恒等关系。

## 回归测试

```powershell
python -X utf8 -B -m unittest -v test_ffxiv_crossclient
```