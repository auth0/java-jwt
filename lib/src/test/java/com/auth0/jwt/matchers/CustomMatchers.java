package com.auth0.jwt.matchers;

import com.auth0.jwt.exceptions.IncorrectClaimException;
import com.auth0.jwt.exceptions.MissingClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.time.Instant;
import java.util.Arrays;

public class CustomMatchers {
    public static Matcher<MissingClaimException> hasMissingClaimName(final String claimName) {
        return new TypeSafeMatcher<MissingClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("MissingClaimException with claim name: "+claimName);
            }

            @Override
            protected boolean matchesSafely(MissingClaimException item) {
                return item.getClaimName().equals(claimName);
            }
        };
    }

    public static Matcher<TokenExpiredException> hasTokenExpiredOn(final Instant instant) {
        return new TypeSafeMatcher<TokenExpiredException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("TokenExpiredException with expired time as: "+instant.getEpochSecond());
            }

            @Override
            protected boolean matchesSafely(TokenExpiredException item) {
                return item.getExpiredOn().equals(instant);
            }
        };
    }

    public static Matcher<IncorrectClaimException> hasClaimName(final String claimName) {
        return new TypeSafeMatcher<IncorrectClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("IncorrectClaimException with claim name: "+claimName);
            }

            @Override
            protected boolean matchesSafely(IncorrectClaimException item) {
                return item.getClaimName().equals(claimName);
            }
        };
    }

    public static <T> Matcher<IncorrectClaimException> hasClaimValue(final Object value, final Class<T> clazz) {
        return new TypeSafeMatcher<IncorrectClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("IncorrectClaimException with claim : "+value);
            }

            @Override
            protected boolean matchesSafely(IncorrectClaimException item) {
                return item.getClaimValue().as(clazz).equals(value);
            }
        };
    }

    public static <T> Matcher<IncorrectClaimException> hasClaimInstant(final Instant value, final Class<T> clazz) {
        return new TypeSafeMatcher<IncorrectClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("IncorrectClaimException with claim : "+value);
            }

            @Override
            protected boolean matchesSafely(IncorrectClaimException item) {
                return item.getClaimValue().as(clazz).equals(value);
            }
        };
    }

    public static <T> Matcher<IncorrectClaimException> hasClaimValueArray(final Object value, final Class<T> clazz) {
        return new TypeSafeMatcher<IncorrectClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("IncorrectClaimException with claim : "+value);
            }

            @Override
            protected boolean matchesSafely(IncorrectClaimException item) {
                return Arrays.equals((Object[]) item.getClaimValue().as(clazz), (Object[])value);
            }
        };
    }

    public static <T> Matcher<IncorrectClaimException> hasNullClaim() {
        return new TypeSafeMatcher<IncorrectClaimException>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("IncorrectClaimException with claim as null");
            }

            @Override
            protected boolean matchesSafely(IncorrectClaimException item) {
                boolean a = item.getClaimValue().isNull();
                String b = item.getClaimValue().toString();
                return item.getClaimValue().isNull();
            }
        };
    }
}
