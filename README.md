# Peng Partial XOR Recovery Toolkit


年初的时候电脑rdp被爆破，导致电脑数据被加密，索性是虚拟机影响不大，最近分析了发现这是可解的，所以写了这个工具。

本工具是针对.peng 和 .kuan 后缀的勒索病毒样本的离线恢复工具。



## 快速开始

### 1. 提取 mask

准备一对原始文件和加密文件（都至少 64KB）提取 mask：

```bash
python3 tools/extract_mask.py \
--original "/path/to/original.mov" \
--encrypted "/path/to/original.mov.[[VictimID]].[[email]].peng" \
--output "masks/peng_mask.bin"
```

### 2. 恢复文件

得到mask（.bin）文件后，就可以开始恢复文件了。

**恢复到新目录（推荐先验证）：**

```bash
python3 tools/recover_peng_partial.py \
--mask-file "masks/peng_mask.bin" \
--encrypted "/path/to/encrypted_dir" \
--output-dir "/path/to/recovered_test"
```

**原地批量恢复（确认 mask 正确后）：**

```bash
python3 tools/restore_peng_inplace.py \
--mask-file "masks/peng_mask.bin" \
--apply --inplace-fast --workers 32 --quiet \
"/path/to/data"
```

## 工具说明

| 工具 | 说明 |
|------|------|
| `extract_mask.py` | 从原始/加密文件对提取 64KB mask |
| `decrypt_peng.py` | 使用 mask 恢复单个 .peng 文件 |
| `recover_peng_partial.py` | 恢复到新目录，不修改原文件 |
| `restore_peng_inplace.py` | 原地批量恢复，适合大规模恢复 |
| `extract_peng_metadata.py` | 批量提取 metadata |
| `evtx_rdp_triage.py` | 从 Windows evtx 提取 RDP/登录事件 |

## 常用参数

- `--apply`: 真正执行恢复（不加时只 dry-run）
- `--inplace-fast`: 原地快速恢复
- `--workers N`: 并发数（建议 16-32）
- `--quiet`: 减少日志输出
- `--limit N`: 只处理前 N 个文件（压测用）

## 已验证类型

`mov, mp4, mkv, jpg, png, avif, wav, mp3, pdf, psd, zip, xml`

## 原理
此勒索病毒采用 xor 加密算法，但是有一部分数据是固定的，可以用原始文件提取出固定数据，然后用固定数据和密文进行 xor 解密。
