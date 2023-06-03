

# RedChef
**Fully automatic penetration test tool using Deep Reinforcement Learning.**  



### DeepExploit System component.  
![System Component](./img/system_component.png)  

DeepExploitは、機械学習モデル（A3C）とMetasploitで構成されている。
A3Cは、RPC APIを介してターゲットサーバにエクスプロイトを実行する。

A3Cは、KerasとTensorflowによって開発され、深層強化学習によってエクスプロイトの実行方法を自己学習するために使用される。自己学習した結果は学習データとして保存され、再利用が可能である。

Metasploitは、世界で最も有名な侵入テストツールであり、A3Cからの指示に基づき、ターゲットサーバーにエクスプロイトを実行するために使用されます。
 
![redchef](./img/redchef.png)  

RedChefの概要図である。DeepExploitで使用されていたA3Cの部分をLedeepChefで用いられていたニューラルエージェントに変更している。
ニューラルエージェントはPOMDPベースのエージェントであり、GRUを基に部分観測情報をエンコードし、アクションの確率を出力する。


![GTrXL](./img/GTrXL.png)

GTrXLの概要図である。こちらはTransformer-xlにGRUの要素入れて過学習を抑え、Transformerを強化学習に適用できるようにした手法である。

![encoder](./img/redchefcontext.png)

RedChef＋GtrXLの手法のエンコーダ部分の図である。 



