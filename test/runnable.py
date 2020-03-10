
class Runnable():
    def __init__(self, func, args):
        self.runnable = func
        self.args = args
        self.ret = None
    
    def run(self):
        self.ret = self.runnable(*self.args)


def add(a,b):
    return a+b

handler = Runnable(add, (1,2))
handler.run()
print(handler.ret)     

