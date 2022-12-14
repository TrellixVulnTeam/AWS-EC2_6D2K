??          ?   %   ?      P  !   Q  !   s  #   ?     ?  ,   ?            >   &  D   e  ;   ?  ?   ?  %   ?  #   ?     ?  $   ?  "        <  ,   M  $   z  %   ?     ?  )   ?       c       ~	  ?  ?	          6     U     s  #   ?     ?     ?  ;   ?  B   	  0   L  ?   }  *   +  *   V     ?  !   ?     ?     ?  !   ?  "     +   '  !   S  *   u     ?  "  ?     ?                                        	                                                                              
       %s: Argument expected after `%s'
 %s: Invalid --process value `%s'
 %s: Invalid process specifier `%s'
 %s: Subject not specified
 %s: Two arguments expected after `--detail'
 %s: Unexpected argument `%s'
 ACTION Authentication is needed to run `$(program)' as the super user Authentication is needed to run `$(program)' as user $(user.display) Authentication is required to run a program as another user Authentication is required to run the polkit example program Frobnicate (user=$(user), user.gecos=$(user.gecos), user.display=$(user.display), program=$(program), command_line=$(command_line)) Close FD when the agent is registered Don't replace existing agent if any FD Only output information about ACTION Output detailed action information PID[,START_TIME] Register the agent for the specified process Register the agent owner of BUS_NAME Report bugs to: %s
%s home page: <%s> Run a program as another user Run the polkit example program Frobnicate Show version Usage:
  pkcheck [OPTION...]

Help Options:
  -h, --help                         Show help options

Application Options:
  -a, --action-id=ACTION             Check authorization to perform ACTION
  -u, --allow-user-interaction       Interact with the user if necessary
  -d, --details=KEY VALUE            Add (KEY, VALUE) to information about the action
  --enable-internal-agent            Use an internal authentication agent if necessary
  --list-temp                        List temporary authorizations for current session
  -p, --process=PID[,START_TIME,UID] Check authorization of specified process
  --revoke-temp                      Revoke all temporary authorizations for current session
  -s, --system-bus-name=BUS_NAME     Check authorization of owner of BUS_NAME
  --version                          Show version

Report bugs to: %s
%s home page: <%s>
 [--action-id ACTION] Project-Id-Version: polkit master
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2016-07-15 17:44+0200
PO-Revision-Date: 2015-11-13 01:59-0500
Last-Translator: Mingye Wang (Arthur2e5) <arthur200126@gmail.com>
Language-Team: Chinese (China) <i18n-zh@googlegroups.com>
Language: zh_CN
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Generator: Poedit 1.8.6
 %s: %s 后预期参数
 %s: 无效 --process 值 "%s"
 %s: 无效进程定义 "%s" 
 %s: 主题未指定
 %s: --detail 后预期两个参数
 %s: 意外的参数 "%s"
 操作 需要授权：作为超级用户身份运行 "$(program)"  需要授权：作为用户 "$(user.display)" 运行 "$(program)"  需要验证：作为另一个用户运行程序 需要验证：运行 polkit 示例程序 Frobnicate (user=$(user), user.gecos=$(user.gecos), user.display=$(user.display), program=$(program), command_line=$(command_line)) 注册助理程序时关闭文件描述符 不替换现有助理程序，若有的话 文件描述符 只输出与操作有关的信息 输出详细的操作信息 PID[,开始时间] 对指定进程注册助理程序 注册 BUS_NAME 的助理所有者 报告错误到：%s
%s 项目主页：<%s> 作为另一个用户运行程序 运行 polkit 示例程序“Frobnicate” 显示版本 用法
  pkcheck [选项...]

帮助选项
  -h, --help                         显示可选的帮助

应用选项
  -a, --action-id=操作               检查 <操作> 的授权情况
  -u, --allow-user-interaction       在必要时进行用户交互
  -d, --details=键 值                将 (键, 值) 加入有关操作的信息
  --enable-internal-agent            在必要时使用内置授权助理程序
  --list-temp                        列出当前会话的临时授权
  -p, --process=PID[,开始时间,UID]    检查指定进程的授权
  --revoke-temp                      吊销所有当前会话的临时授权
  -s, --system-bus-name=BUS_NAME     检查 BUS_NAME 所有者的授权
  --version                          显示版本

报告错误到：%s
%s 项目主页：<%s>
 [--action-id 操作] 