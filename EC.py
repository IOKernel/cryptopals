class EC:
    def __init__(self, a, b, p, g=None):
        self.p = int(p)
        self.a = int(a)
        self.b = int(b)
        if not g:
            self.g = self.find_generator()
        else:
            self.g = int(g)
    
    def find_generator(self):
        for i in range(2, self.p):
            if self.is_generator(i):
                return i

    def is_generator(self, g):
        if g == 1:
            return False
        if self.p % g == 0:
            return False
        if self.legendre(g) != 1:
            return False
        return True

    def legendre(self, x):
        if x == 1:
            return 1
        if x % 2 == 0:
            return self.legendre(x // 2)
        return -self.legendre(self.p % x)
    
    def Point(self, x, y):
        if x == 0 and y == 0:
            return EC_Point(x, y, self)
        if self.is_valid_point(x, y):
            return EC_Point(x, y, self)
        raise Exception("Point is not valid on the curve")
    
    def is_valid_point(self, x, y):
        # E: Y**2 = X**3 + a*X + b, mod p
        return (y*y) % self.p == (x*x*x + self.a*x + self.b) % self.p

    def _compute_y(self, x):
        y2 = (x * x * x + self.a * x + self.b) % self.p
        return tonelli(y2, self.p)

class EC_Point():
    def __init__(self, x: int, y: int, curve: EC):
        self.x = x
        self.y = y
        self.curve = curve
        self.p = curve.p
        self.a = curve.a
        self.b = curve.b

    def __repr__(self) -> str:
        return f"EC_Point({self.x}, {self.y})"
        
    def __eq__(self, other: object) -> bool:
        '''
        check if two points are equal
        '''
        # check if other is not an EC_Point
        if isinstance(other, EC_Point):
            return self.x == other.x and self.y == other.y

        # check if it is a tuple
        if isinstance(other, tuple):
            return self.x == other[0] and self.y == other[1]

    def __neg__(self):
        '''
        negate the point (x, y) = (x, -y)
        '''
        return EC_Point(self.x, -self.y % self.p, self.curve)

    def __add__(self, other):
        '''
        add two points (x1, y1) and (x2, y2)
        input: two EC_Point objects or EC_Point and tuple
        output: EC_Point object
        '''
        if isinstance(other, tuple):
            other = self.curve.Point(other[0], other[1])

        # check if both points are on the same curve
        if self.curve != other.curve:
            raise Exception("Points are not on the same curve")
        # check if P = 0
        if self.x == 0 and self.y == 0:
            return other
        # check if Q = 0
        if other.x == 0 and other.y == 0:
            return self
        # check if Q = -P
        if other.x == self.x and other.y == -self.y:
            return EC_Point(0, 0, self.curve)

        # if P == Q, then we want to return 2P
        if self.x == other.x and self.y == other.y:
            s = (3 * self.x * self.x + self.a) * self.modinv(2 * self.y, self.p)
        else:
            s = (other.y - self.y) * self.modinv((other.x - self.x) % self.p, self.p)

        x3 = (s * s - self.x - other.x) % self.p
        y3 = (s * (self.x - x3) - self.y) % self.p
        return EC_Point(x3, y3, self.curve)

    def __mul__(self, n):
        '''
        multiply a point by a scalar
        x * y => x.__mul__(y)
        input: Point multiplied by scalar
        output: EC_Point object
        '''
        Q = self
        R = self.curve.Point(0, 0)
        while n > 0:
            if n % 2 == 1:
                R = R + Q
            Q = Q + Q
            n = n // 2
        return EC_Point(R.x, R.y, self.curve)

    def modinv(self, a, m):
        return pow(a, -1, m)
        
def legendre(x, p):
    return pow(x, (p - 1) // 2, p)

def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r
