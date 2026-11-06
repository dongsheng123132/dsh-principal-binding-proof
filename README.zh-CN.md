# dsh-principal-binding-proof

作者 / 维护者：He Fangsheng (贺方升 / 贺去病; Dosen)· [hequbing.com](https://www.hequbing.com)

离线、内容寻址的“主体绑定证据层”：验证同一个伪名 authority 与 tenant 是否沿 principal → session → agent → tool-call → runtime → artifact 保持一致，并检查 revision、key epoch、新鲜度、允许 issuer、有效期、撤销、相邻关系和唯一无环链。

它专抓身份替换、跨租户串线、陈旧身份、断链、关系错位、未授权 issuer 与最终 artifact 错绑。它不做登录、认证、授权、签名验证或远程传输，不读取账户、凭据、提示词和正文，也不执行命令。

与 `dsh-decision-effect-proof`、`dsh-attestation-proof`、`dsh-lineage` 互补，不实现第二套权限核心。示例见 [`examples/bound.json`](examples/bound.json)。
