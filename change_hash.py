import hashlib
salt = "11ee677a51f1ea05"          # 테이블의 salt 값
password = "wjdghwls9907!!"        # 실제 로그인에 쓸 비밀번호
print(hashlib.sha256((salt + password).encode("utf-8")).hexdigest())
