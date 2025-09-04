import hashlib

#password
pw="jhok"
pw1="sylee"
pw2="icim"
pw3="lsyeom"
pw4="dyjang"
pw5="smahn"
pw6="dlarbtjq1!"
pw7="wjdghwls9907!!"
pw8="yelee"
pw9="smlee"
pw10="yhpark"
pw11="dcahn"
pw12="jseom"
pw13="dskwon"
pw14="ghlee"
pw15="sukim"
pw16="spahn"
pw17="lemanhthang"

#salt==============
salt="4qGyvApTkS2a1eLD"
salt1="C9kBopvlgRrI3WVu"
salt2="5wbGqFaprtF7HYzu"
salt3="yNSfOcihWn0rJD9u"
salt4="1aW0CTbD4rj9tOeH"
salt5="bKjTzQfVpPwX1CgO"
salt6="RoH3gW7syIdlqYAz"
salt7="11ee677a51f1ea05"
salt8="OQwF52Tb7XU1R3Hc"
salt9="ZC9uK1Bfqd4O3gFp"
salt10="xr5bF7o2YgP8VjMh"
salt11="3PGLX2aUsjYFqivT"
salt12="8hXQqVrZL4bkN2wC"
salt13="p9uT1Am2c4R5oIZd"
salt14="tkp8S0hDMCaN6w1e"
salt15="l7bwHoJfWqNG5k0C"
salt16="Ygzj0Gcb8fVQ9eK3"
salt17="u7OshnK8EcW4xQvJ"

print(hashlib.sha256((salt + pw).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt1 + pw1).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt2 + pw2).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt3 + pw3).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt4 + pw4).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt5 + pw5).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt6 + pw6).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt7 + pw7).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt8 + pw8).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt9 + pw9).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt10 + pw10).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt11 + pw11).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt12 + pw12).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt13 + pw13).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt14 + pw14).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt15 + pw15).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt16 + pw16).encode("utf-8")).hexdigest())
print(hashlib.sha256((salt17 + pw17).encode("utf-8")).hexdigest())
