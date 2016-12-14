package com.auth0.jwt.impl;

import com.auth0.jwt.UserPojo;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.NullNode;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static com.auth0.jwt.impl.JsonNodeClaim.claimFromNode;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class JsonNodeClaimTest {

    private ObjectMapper mapper;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        mapper = getDefaultObjectMapper();
    }

    @Test
    public void shouldGetBooleanValue() throws Exception {
        JsonNode value = mapper.valueToTree(true);
        Claim claim = claimFromNode(value);

        assertThat(claim.asBoolean(), is(notNullValue()));
        assertThat(claim.asBoolean(), is(true));
    }

    @Test
    public void shouldGetNullBooleanIfNotBooleanValue() throws Exception {
        JsonNode objectValue = mapper.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asBoolean(), is(nullValue()));
        JsonNode stringValue = mapper.valueToTree("boolean");
        assertThat(claimFromNode(stringValue).asBoolean(), is(nullValue()));
    }

    @Test
    public void shouldGetIntValue() throws Exception {
        JsonNode value = mapper.valueToTree(123);
        Claim claim = claimFromNode(value);

        assertThat(claim.asInt(), is(notNullValue()));
        assertThat(claim.asInt(), is(123));
    }

    @Test
    public void shouldGetNullIntIfNotIntValue() throws Exception {
        JsonNode objectValue = mapper.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asInt(), is(nullValue()));
        JsonNode stringValue = mapper.valueToTree("123");
        assertThat(claimFromNode(stringValue).asInt(), is(nullValue()));
    }

    @Test
    public void shouldGetDoubleValue() throws Exception {
        JsonNode value = mapper.valueToTree(1.5);
        Claim claim = claimFromNode(value);

        assertThat(claim.asDouble(), is(notNullValue()));
        assertThat(claim.asDouble(), is(1.5));
    }

    @Test
    public void shouldGetNullDoubleIfNotDoubleValue() throws Exception {
        JsonNode objectValue = mapper.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asDouble(), is(nullValue()));
        JsonNode stringValue = mapper.valueToTree("123.23");
        assertThat(claimFromNode(stringValue).asDouble(), is(nullValue()));
    }

    @Test
    public void shouldGetDateValue() throws Exception {
        JsonNode value = mapper.valueToTree(1476824844L);
        Claim claim = claimFromNode(value);

        assertThat(claim.asDate(), is(notNullValue()));
        assertThat(claim.asDate(), is(new Date(1476824844L * 1000)));
    }

    @Test
    public void shouldGetNullDateIfNotDateValue() throws Exception {
        JsonNode objectValue = mapper.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asDate(), is(nullValue()));
        JsonNode stringValue = mapper.valueToTree("1476824844");
        assertThat(claimFromNode(stringValue).asDate(), is(nullValue()));
    }

    @Test
    public void shouldGetStringValue() throws Exception {
        JsonNode value = mapper.valueToTree("string");
        Claim claim = claimFromNode(value);

        assertThat(claim.asString(), is(notNullValue()));
        assertThat(claim.asString(), is("string"));
    }

    @Test
    public void shouldGetNullStringIfNotStringValue() throws Exception {
        JsonNode objectValue = mapper.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asString(), is(nullValue()));
        JsonNode intValue = mapper.valueToTree(12345);
        assertThat(claimFromNode(intValue).asString(), is(nullValue()));
    }

    @Test
    public void shouldGetArrayValueOfCustomClass() throws Exception {
        JsonNode value = mapper.valueToTree(new UserPojo[]{new UserPojo("George", 1), new UserPojo("Mark", 2)});
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(UserPojo.class), is(notNullValue()));
        assertThat(claim.asArray(UserPojo.class), is(arrayContaining(new UserPojo("George", 1), new UserPojo("Mark", 2))));
    }

    @Test
    public void shouldGetArrayValue() throws Exception {
        JsonNode value = mapper.valueToTree(new String[]{"string1", "string2"});
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(notNullValue()));
        assertThat(claim.asArray(String.class), is(arrayContaining("string1", "string2")));
    }

    @Test
    public void shouldGetNullArrayIfNullValue() throws Exception {
        JsonNode value = mapper.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayIfNonArrayValue() throws Exception {
        JsonNode value = mapper.valueToTree(1);
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(nullValue()));
    }

    @Test
    public void shouldThrowIfArrayClassMismatch() throws Exception {
        JsonNode value = mapper.valueToTree(new String[]{"keys", "values"});
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.asArray(UserPojo.class);
    }

    @Test
    public void shouldGetListValueOfCustomClass() throws Exception {
        JsonNode value = mapper.valueToTree(Arrays.asList(new UserPojo("George", 1), new UserPojo("Mark", 2)));
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(UserPojo.class), is(notNullValue()));
        assertThat(claim.asList(UserPojo.class), is(hasItems(new UserPojo("George", 1), new UserPojo("Mark", 2))));
    }

    @Test
    public void shouldGetListValue() throws Exception {
        JsonNode value = mapper.valueToTree(Arrays.asList("string1", "string2"));
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(notNullValue()));
        assertThat(claim.asList(String.class), is(hasItems("string1", "string2")));
    }

    @Test
    public void shouldGetNullListIfNullValue() throws Exception {
        JsonNode value = mapper.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(nullValue()));
    }

    @Test
    public void shouldGetNullListIfNonArrayValue() throws Exception {
        JsonNode value = mapper.valueToTree(1);
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(nullValue()));
    }

    @Test
    public void shouldThrowIfListClassMismatch() throws Exception {
        JsonNode value = mapper.valueToTree(new String[]{"keys", "values"});
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.asList(UserPojo.class);
    }

    @Test
    public void shouldGetCustomClassValue() throws Exception {
        JsonNode value = mapper.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim.as(UserPojo.class).getName(), is("john"));
        assertThat(claim.as(UserPojo.class).getId(), is(123));
    }

    @Test
    public void shouldThrowIfCustomClassMismatch() throws Exception {
        JsonNode value = mapper.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.as(String.class);
    }

    @SuppressWarnings({"unchecked", "RedundantCast"})
    @Test
    public void shouldGetAsMapValue() throws Exception {
        JsonNode value = mapper.valueToTree(Collections.singletonMap("key", new UserPojo("john", 123)));
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        Map map = claim.as(Map.class);
        assertThat(((Map<String, Object>) map.get("key")), hasEntry("name", (Object) "john"));
        assertThat(((Map<String, Object>) map.get("key")), hasEntry("id", (Object) 123));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingMissingNode() throws Exception {
        JsonNode value = MissingNode.getInstance();
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(NullClaim.class)));
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingNullNode() throws Exception {
        JsonNode value = NullNode.getInstance();
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(NullClaim.class)));
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingNullValue() throws Exception {
        JsonNode value = mapper.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(NullClaim.class)));
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldReturnValidButNullClaimIfTreeIsEmpty() throws Exception {
        JsonNode value = mapper.valueToTree(new Object());
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(true));
    }
}