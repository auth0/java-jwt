package com.auth0.jwt;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import com.jayway.jsonassert.JsonAssert;

import java.lang.reflect.Array;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class JsonMatcher extends TypeSafeDiagnosingMatcher<String> {

    private final String entry;
    private final String key;
    private final Matcher matcher;
    private final Matcher entryMatcher;

    private JsonMatcher(String key, Object value, Matcher valueMatcher, Matcher entryMatcher) {
        this.key = key;
        this.matcher = valueMatcher;
        this.entryMatcher = entryMatcher;
        if (value != null) {
            String stringValue = objectToString(value);
            entry = getStringKey(key) + stringValue;
        } else {
            entry = null;
        }
    }

    @Override
    protected boolean matchesSafely(String item, Description mismatchDescription) {
        if (item == null) {
            mismatchDescription.appendText("JSON was null");
            return false;
        }
        if (entryMatcher != null) {
            try {
                JsonAssert.with(item).assertThat(key, entryMatcher);
                return true;
            } catch (AssertionError ae) {
                matcher.describeMismatch(item, mismatchDescription);
                return false;
            } catch (Exception e) {
                matcher.describeMismatch(item, mismatchDescription);
                return false;
            }
        }

        if (matcher != null) {
            if (!matcher.matches(item)) {
                matcher.describeMismatch(item, mismatchDescription);
                return false;
            }
            if (!item.contains(getStringKey(key))) {
                mismatchDescription.appendText("JSON didn't contained the key ").appendValue(key);
                return false;
            }
        }
        if (entry != null && !item.contains(entry)) {
            mismatchDescription.appendText("JSON was ").appendValue(item);
            return false;
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        if (matcher == null) {
            description.appendText("A JSON with entry ")
                    .appendValue(entry);
        } else {
            matcher.describeTo(description);
        }
    }

    public static JsonMatcher hasEntry(String key, Object value) {
        return new JsonMatcher(key, value, null, null);
    }

    public static JsonMatcher hasEntry(String key, Matcher valueMatcher) {
        return new JsonMatcher(key, null, valueMatcher, null);
    }

    public static JsonMatcher hasJsonPath(String jsonPath, Matcher entryMatcher) {
        return new JsonMatcher(jsonPath, null, null, entryMatcher);
    }

    private String getStringKey(String key) {
        return "\"" + key + "\":";
    }

    private String objectToString(Object value) {
        String stringValue;
        if (value == null) {
            stringValue = "null";
        } else if (value instanceof String) {
            stringValue = "\"" + value + "\"";
        } else if (value instanceof Map) {
            stringValue = mapToString((Map<String, Object>) value);
        } else if (value instanceof Array) {
            stringValue = arrayToString((Object[]) value);
        } else if (value instanceof List) {
            stringValue = listToString((List<Object>) value);
        } else {
            stringValue = value.toString();
        }
        return stringValue;
    }

    private String arrayToString(Object[] array) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < array.length; i++) {
            Object o = array[i];
            sb.append(objectToString(o));
            if (i + 1 < array.length) {
                sb.append(",");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String listToString(List<Object> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        Iterator<Object> it = list.iterator();
        while (it.hasNext()) {
            Object o = it.next();
            sb.append(objectToString(o));
            if (it.hasNext()) {
                sb.append(",");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String mapToString(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Object> e = it.next();
            sb.append("\"" + e.getKey() + "\":" + objectToString(e.getValue()));
            if (it.hasNext()) {
                sb.append(",");
            }
        }
        sb.append("}");
        return sb.toString();
    }
}
