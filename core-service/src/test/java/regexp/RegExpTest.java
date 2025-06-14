package regexp;

import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class RegExpTest {

    // 정규표현식 : 패턴에 일치하는 문자열을 검색, 치환, 추출하는 데 사용되는 표현식

    @Test
    void testBasic(){
        String str = "spring java javascript html";
        Pattern regExp = Pattern.compile("script");
        Matcher match = regExp.matcher(str);
        
        if(match.find()){
            System.out.println(match.group());
        }
    }
    
    @Test
    void testAnchor(){
        // ^, $
        // ^ : 뒤에 오는 패턴으로 시작하는
        // $ : 앞에 오는 패턴으로 끝나는
        String str = "spring java javascript html";
        String str2 = "html java javascript spring";
        
        Matcher m1 = Pattern.compile("^spring").matcher(str);
        Matcher m2 = Pattern.compile("spring$").matcher(str2);
        
        assertTrue(m1.find());
        assertTrue(m2.find());
    }
    
    @Test
    void testFlag(){
        // g, i, m
        // g : 하나 이상의 매칭되는 결과를 탐색 (java 에서는 default)
        // i : 대소문자 구분 없이 검색
        // m : 모든 행에 대해 패턴을 검색
        String str = "spring\njava\nJAvascript\nhtml";
        Matcher m1 = Pattern.compile("^ja", Pattern.MULTILINE).matcher(str);
        System.out.println(m1.results().map(MatchResult::group).toList());
        
        Matcher m2 = Pattern.compile("(?mi)^ja").matcher(str);
        System.out.println(m2.results().map(MatchResult::group).toList());
    }
    
    @Test
    void testCharacterSet(){
        // 문자셋
        // [] ex) [abcd]
        // 문자셋 안의 각 문자들은 or 로 취급
        // 패턴에 부합하는 여러 캐이스를 작성해야할 때 사용
        // 문자셋 안에서는 이스케이프 문자도 일반문자로 취급
        // ^ 문자셋 내부에서는 not 으로 취급된다.
        
        // 1. 숫자 : [0-9] == [0,1,2,3,4,5,6,7,8,9]
        // 2. 알파벳 소문자 : [a-z]
        // 3. 알파벳 대문자 : [A-Z]
        // 4. 전체 알파벳 : [a-zA-Z]
        // 5. 전체 한글 : [ㄱ-힣]
        // 6. 특수 문자 : [^a-zA-Zㄱ-힣0-9]
        
        String str = "가나다라spring\njava21\nJAvascript19\n!!html";
        Matcher m1 = Pattern.compile("(?mi)[sprzaq]").matcher(str);
        System.out.println(m1.results().map(MatchResult::group).toList());
        
        Matcher m2 = Pattern.compile("(?mi)[ㄱ-힣]").matcher(str);
        System.out.println(m2.results().map(MatchResult::group).toList());
        
        Matcher m3 = Pattern.compile("(?mi)[^a-zA-Zㄱ-힣0-9]").matcher(str);
        System.out.println(m3.results().map(MatchResult::group).toList());
        
        Matcher m4 = Pattern.compile("(?mi)[a-zA-Z]").matcher(str);
        System.out.println(m4.results().map(MatchResult::group).toList());
    }
    
    @Test
    void pracRegExp1(){
        // 숫자 6자리 - 숫자 7자리
        // 월의 첫번째 자리에는 0,1
        // 일의 첫번째 자리 0~3
        // -  뒤의 첫 자리는 1~4
        String reg = "^[0-9][0-9][01][0-9][0123][0-9]-[1-4][0-9][0-9][0-9][0-9][0-9][0-9]$";
        Pattern pattern = Pattern.compile(reg);
        assertTrue(pattern.matcher("991212-1222222").matches());
        assertFalse(pattern.matcher("991212-8222222").matches());
    }
    
    @Test
    void testSpecial(){
        
        // 특수 문자
        // . : 개행문자를 제외한 모든 단일 문자
        // \d : 숫자 == [0-9]
        // \D : [^0-9]
        // \w : 밑줄 문자를 포함한 영수문자 : [a-zA-Z0-9_]
        // \W :[^a-zA-Z0-9_]
        
        // 수량 문자
        // + : 1개 이상
        // * : 0개 이상
        // ? : 0개 또는 1개 존재
        // {n} : n개
        // {n, m} : n ~ m개
        // {n,} : n개 이상
        
        // 숫자 6자리 - 숫자 7자리
        // 월의 첫번째 자리에는 0,1
        // 일의 첫번째 자리 0~3
        // -  뒤의 첫 자리는 1~4
        String reg = "^\\d{2}[01]\\d[0123]\\d-[1-4]\\d{6}$";
        Pattern pattern = Pattern.compile(reg);
        assertTrue(pattern.matcher("991212-1222222").matches());
        assertFalse(pattern.matcher("991912-1222222").matches());
    }
    
    @Test
    void testGroup(){
        // ()
        // |  : or
        // 숫자 6자리 - 숫자 7자리
        // 주민등록 3번째 자리에는 0,1 만 올 수 있다.
        // 3번째 자리에 1이 올 경우 4번째 자리는 0,1,2 만 올 수 있다.
        
        // 주민등록번호의 다섯번째 자리에는 0~3 사이의 숫자만 올 수 있다.
        // 다섯번째 자리에 3이 올 경우 6번째 자리의 숫자는 0,1 만 올 수 있다.
        
        // 주민번호의 8번째 자리에는 1~4 사이의 숫자만 올 수 있다.
        String reg = "^\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])-[1-4]\\d{6}$";
        Pattern pattern = Pattern.compile(reg);
        assertTrue(pattern.matcher("991212-1222222").matches());
        assertFalse(pattern.matcher("991930-1222222").matches());
    }
    
    @Test
    void lookahead(){
        // 전위 탐색자 : 전위 탐색자의 패턴에 일치하는 문자를 탐색
        // 패턴(전위탐색패턴)
        // 패턴A(?=패턴)
        // 패턴A(?!패턴)
        
        String str = "https://www.naver.com:";
        String reg = ".{5}(?=:)";
        
        Matcher matcher = Pattern.compile(reg).matcher(str);
        System.out.println(matcher.results().map(MatchResult::group).toList());
    }
    
    @Test
    void testPasswordValidation(){
        // 숫자, 영문자, 특수문자가 1개이상 포함된 8자리 이상의 문자열
        String reg = "^(?=.*\\d)(?=.*[a-zA-Z])(?=.*[^a-zA-Zㄱ-힣])(?!.*[ㄱ-힣]).{8,}$";
        Matcher m1 = Pattern.compile(reg).matcher("123abc");
        Matcher m2 = Pattern.compile(reg).matcher("123abc!");
        Matcher m3 = Pattern.compile(reg).matcher("123abcㄱ");
        Matcher m4 = Pattern.compile(reg).matcher("123abc!@#");
        
        assertFalse(m1.matches());
        assertFalse(m2.matches());
        assertFalse(m3.matches());
        assertTrue(m4.matches());
    }
}
