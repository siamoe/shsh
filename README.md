删除相关端口转发
如果我们多次运行脚本转发端口，有些不使用了，需要删除，则按要求操作命令：

#查看全部转发端口配置文件，格式为brook_8888.service，8888为本地转发的端口

  ```bash
  ls /etc/init.d/brook_*
  ```

#停止端口转发，8888为你需要停止的本地转发的端口，自行修改

  ```bash
  rc-service brook_8888 stop
  ```

#删除端口转发，8888为你需要停止的本地转发的端口，自行修改

  ```bash
  rc-update del brook_8888
  ```
然后
  ```bash
  rm /etc/init.d/brook_8888
  ```

运行完成后，指定端口转发会彻底删除。


- **启动服务**：
  ```bash
  rc-service brook_8888 start
  ```

- **重启服务**：
  ```bash
  rc-service brook_8888 restart
  ```

- **查看服务状态**：
  ```bash
  rc-service brook_8888 status
  ```
  
- **禁用服务开机自启**：
  ```bash
  rc-update add brook_8888 default
  ```
