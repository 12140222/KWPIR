# KWPIR
# 编译
javac -encoding UTF-8 -d bin src/*.java

# 运行预处理测试
java -cp bin TestTask1

# 运行端到端测试
java -cp bin TestEndToEnd


## 项目结构


  ## DataOwner.java
  数据拥有者：预处理（分桶、Merkle树、Hint）
  Server.java         # 服务器：查询处理
  Client.java         # 客户端：查询生成、解码、Merkle验证
  TestTask1.java      # 预处理阶段测试
  TestEndToEnd.java   # 完整协议端到端测试
