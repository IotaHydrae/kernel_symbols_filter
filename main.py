

import os
import sys

# 关键字，逗号隔开
keywords = r'''vfs,fsnotify,dnotify,inotify,fuse,ext4'''
# filter_out = '''__ksymtab,__kcrctab,__kstrtab'''


class SymsFilter(object):

    def __init__(self, path_data_file=None):

        print("Filter init.")
        self.path_data_file = path_data_file
        self.list_keywords = keywords.split(",")
        self.list_sym = []

        self.list_sym_filtered = []
        # print(self.list_keywords)
        pass

    # 处理文件
    def process_origin_data(self) -> bool:

        ret = False
        if self.path_data_file == None:
            exit()
        else:
            with open(file=self.path_data_file, mode="r+", encoding="utf-8") as fil:
                tmp_fil_lines = list(fil)
                # print(tmp_fil_lines)
                for line in tmp_fil_lines:
                    self.list_sym.append(line.split(" ")[-1].split("\n")[0])
                fil.close()

        return ret

    def my_filter(self, origin_list) -> list:
        # for item in origin_list:

        pass

    # 过滤符号
    def parse(self, mode='ifin') -> None:

        if mode == 'startswith':
            pass
        elif mode == 'ifin':
            tmp_list = []
            for key in self.list_keywords:
                tmp_list.append(list(filter(lambda symbol, key_in=key:
                                            # conditions not starts with
                                            not symbol.startswith("_")            and
                                            not symbol.startswith("__")           and
                                            not symbol.startswith("do")           and
                                            not symbol.startswith("ftrace")       and
                                            not symbol.startswith("perf")         and
                                            not symbol.startswith("netlink")      and
                                            not symbol.startswith("event")        and
                                            not symbol.startswith("selinux")      and
                                            not symbol.startswith("security")     and
                                            not symbol.startswith("rfcomm")       and
                                            not symbol.startswith("rmnet")        and
                                            not symbol.startswith("print")        and
                                            not symbol.startswith("compat")       and
                                            not symbol.startswith("diag")         and
                                            not symbol.startswith("jtag")         and
                                            not symbol.startswith("coresight")    and
                                            not symbol.startswith("ipa")          and
                                            not symbol.startswith("cpr")          and
                                            not symbol.startswith("cap")          and
                                            not symbol.startswith("SyS")          and
                                            not symbol.startswith("dquot")        and
                                            not symbol.startswith("key")          and
                                            not symbol.startswith("proc")         and
                                            not symbol.startswith("msmcobalt")    and
                                            not symbol.startswith("mdss")         and
                                            not symbol.startswith("msc")          and
                                            not symbol.startswith("a5xx")         and
                                            not symbol.startswith("a530")         and
                                            # not symbol.startswith("show")         and
                                            not symbol.startswith("tomtom")       and
                                            not symbol.startswith("tasha")        and
                                            not symbol.startswith("a3xx")         and
                                            not symbol.startswith("adreno")       and
                                            not symbol.startswith("zcache")       and
                                            not symbol.startswith("boost")        and
                                            not symbol.startswith("mem")          and
                                            not symbol.startswith("msm")          and
                                            not symbol.startswith("sys")          and
                                            not symbol.startswith("register")     and
                                            not symbol.startswith("unregister")   and
                                            # conditions not ends with
                                            not symbol.endswith("ops")            and
                                            not symbol.endswith("fops")           and
                                            not symbol.endswith("operations")     and
                                            key_in in symbol                      and
                                            # conditions not in
                                            '.'                     not in symbol and
                                            'quota'                 not in symbol and
                                            'alloc'                 not in symbol and
                                            'attr'                  not in symbol and
                                            'back'                  not in symbol and
                                            'bitmap'                not in symbol and
                                            'cleanup'               not in symbol and
                                            'cache'                 not in symbol and
                                            'close'                 not in symbol and
                                            'copy'                  not in symbol and
                                            'callback'              not in symbol and
                                            'debugfs'               not in symbol and
                                            'devfs'                 not in symbol and
                                            'drv'                   not in symbol and
                                            'dir'                   not in symbol and
                                            '_do_'                  not in symbol and
                                            '_es'                   not in symbol and
                                            '_ext'                  not in symbol and
                                            'flush'                 not in symbol and
                                            '_fh_'                  not in symbol and
                                            'get'                   not in symbol and
                                            'offset'                not in symbol and
                                            'setup'                 not in symbol and
                                            'release'               not in symbol and
                                            'remove'                not in symbol and
                                            'request'               not in symbol and
                                            'rename'                not in symbol and
                                            'destroy'               not in symbol and
                                            'free'                  not in symbol and
                                            'kill'                  not in symbol and
                                            'lock'                  not in symbol and
                                            'link'                  not in symbol and
                                            'stat'                  not in symbol and
                                            'seek'                  not in symbol and
                                            'send'                  not in symbol and
                                            'sync'                  not in symbol and
                                            'show'                  not in symbol and
                                            'sum'                   not in symbol and
                                            'num'                   not in symbol and
                                            'ind'                   not in symbol and
                                            'inode'                 not in symbol and
                                            'msm89'                 not in symbol and
                                            '_mb'                   not in symbol and
                                            'ioctl'                 not in symbol and
                                            'probe'                 not in symbol and
                                            'match'                 not in symbol and
                                            'mutex'                 not in symbol and
                                            'update'                not in symbol and
                                            'del'                   not in symbol and
                                            'put'                   not in symbol and
                                            'end'                   not in symbol and
                                            'error'                 not in symbol and
                                            'success'               not in symbol and
                                            'ok'                    not in symbol and
                                            'unused'                not in symbol and
                                            'prepare'               not in symbol and
                                            'type'                  not in symbol and
                                            'type'                  not in symbol and
                                            'exit'                  not in symbol and
                                            '_bh_'                  not in symbol and
                                            '_li_'                  not in symbol and
                                            'info'                  not in symbol and
                                            'group'                  not in symbol and
                                            'dbgfs'   not in symbol, self.list_sym)))

            self.list_sym_filtered = [
                symbol for list in tmp_list for symbol in list]

            pass
        else:
            pass

    # 写入文件
    def write2file(self) -> None:
        if len(self.list_sym_filtered) > 0:
            with open("./output.txt", 'w+') as fout:
                for symbol in self.list_sym_filtered:
                    fout.write(symbol)
                    fout.write("\n")
                    print(symbol)
                fout.close
        print("symbol filterd count: ",len(self.list_sym_filtered))

def help() -> None:
    print(f'Usage: python {sys.argv[0]} <file path> ...')
    pass


def main() -> None:
    if len(sys.argv) < 2:
        help()
        exit()
    else:
        if os.path.exists(sys.argv[1]):
            filter = SymsFilter(sys.argv[1])
            filter.process_origin_data()
            filter.parse(mode='ifin')
            filter.write2file()


def debug_main() -> None:
    # m_str = 'test'
    # print('tty' in m_str)

    filter = SymsFilter("./all-kallsysms.txt")
    filter.process_origin_data()
    filter.parse(mode='ifin')
    # filter.write2file()
    test_str = "vfs_lock_file"

    # print(re.search(r'bpf', test_str, re.I) == None)



if __name__ == "__main__":
    main()
    # debug_main()

