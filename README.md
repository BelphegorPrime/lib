# lib

## func RandStringWithCharset(length int, charset string) string
Returns a random string with length and a charset (e.g. "abcdefghijklmnopqrstuvwxyz0123456789").
```
str = RandStringWithCharset(5,"abcd")
```
The above command will return a string of length = 5 having random characters from the set "abcd". 

## func RandString(length int) string
Returns a random string with length and the charset ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").
```
str = RandString(5)
```
The above command will return a random string of length = 5.

## func ShuffleIntSlice(slice []int)
shuffles all entries of an `[]int`
```
arr:= [5]int{1,2,3,4,5}
ShuffleIntSlice(arr[:])
```

## func ShuffleStringSlice(slice []string)
shuffles all entries of an `[]string`
```
string_arr:= [3]string{"git","rocks","hello"}
ShuffleStringSlice(string_arr[:])
```

## func ShuffleByteSlice(slice []byte)
shuffles all entries of an `[]byte`
```
byte_arr:= [3]byte{'g','r','h'}
ShuffleByteSlice(byte_arr[:])
```

## func UpArrow(base uint64, exponant uint64, upArrowAmount uint64) uint64
computes the upArrow function (https://en.wikipedia.org/wiki/Knuth%27s_up-arrow_notation)
```
res = UpArrow(2,4,1) //output will be 16
```

## func GetRequestContentFromRequest(req *http.Request) map[string]interface{}
returns the JSON from an `http.Request`

## func GetRequestContentFromResponse(resp *http.Response) map[string]interface{}
returns the JSON from an `http.Response`

## func IntRange(args ...int) <-chan int
takes 1 to 3 arguments
#### for one argument:
* `IntRange(10)` 
returns :
* `0 1 2 3 4 5 6 7 8 9`

#### for two arguments:
* `IntRange(10, 20)` 
returns :
* `10 11 12 13 14 15 16 17 18 19`

#### for three arguments:
* `IntRange(20, 0, -1)` 
returns :
* `20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1`

## func SieveOfEratosthenes(numberOfPrimes int64) []int64
returns a slice of prime numbers smaller than the parameter `numberOfPrimes`.
* `SieveOfEratosthenes(20)`
returns :
* `2 3 5 7 11 13 17 19`
