package com.auth0.jwt.impl;

import com.auth0.jwt.UserPojo;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.deser.DeserializationContextExt;
import tools.jackson.databind.node.JsonNodeType;
import tools.jackson.databind.node.MissingNode;
import tools.jackson.databind.node.NullNode;
import tools.jackson.databind.node.ObjectNode;
import org.hamcrest.collection.IsMapContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentMatchers;
import tools.jackson.databind.ser.SerializationContextExt;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class JsonNodeClaimTest {

    private DeserializationContextExt context;
    private SerializationContextExt writeContext;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() {
        ObjectMapper objectMapper = getDefaultObjectMapper();
        context = objectMapper._deserializationContext();
        writeContext = objectMapper._serializationContext();
    }

    @Test
    public void shouldGetBooleanValue() {
        JsonNode value = writeContext.valueToTree(true);
        Claim claim = claimFromNode(value);

        assertThat(claim.asBoolean(), is(notNullValue()));
        assertThat(claim.asBoolean(), is(true));
    }

    private Claim claimFromNode(JsonNode value) {
        return JsonNodeClaim.claimFromNode(value, context);
    }

    @Test
    public void shouldGetNullBooleanIfNotBooleanValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asBoolean(), is(nullValue()));
        JsonNode stringValue = writeContext.valueToTree("boolean");
        assertThat(claimFromNode(stringValue).asBoolean(), is(nullValue()));
    }

    @Test
    public void shouldGetIntValue() {
        JsonNode value = writeContext.valueToTree(123);
        Claim claim = claimFromNode(value);

        assertThat(claim.asInt(), is(notNullValue()));
        assertThat(claim.asInt(), is(123));
    }

    @Test
    public void shouldGetNullIntIfNotIntValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asInt(), is(nullValue()));
        JsonNode stringValue = writeContext.valueToTree("123");
        assertThat(claimFromNode(stringValue).asInt(), is(nullValue()));
    }

    @Test
    public void shouldGetLongValue() {
        JsonNode value = writeContext.valueToTree(Long.MAX_VALUE);
        Claim claim = claimFromNode(value);

        assertThat(claim.asLong(), is(notNullValue()));
        assertThat(claim.asLong(), is(Long.MAX_VALUE));
    }

    @Test
    public void shouldGetNullLongIfNotIntValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asLong(), is(nullValue()));
        JsonNode stringValue = writeContext.valueToTree("" + Long.MAX_VALUE);
        assertThat(claimFromNode(stringValue).asLong(), is(nullValue()));
    }

    @Test
    public void shouldGetDoubleValue() {
        JsonNode value = writeContext.valueToTree(1.5);
        Claim claim = claimFromNode(value);

        assertThat(claim.asDouble(), is(notNullValue()));
        assertThat(claim.asDouble(), is(1.5));
    }

    @Test
    public void shouldGetNullDoubleIfNotDoubleValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asDouble(), is(nullValue()));
        JsonNode stringValue = writeContext.valueToTree("123.23");
        assertThat(claimFromNode(stringValue).asDouble(), is(nullValue()));
    }

    @Test
    public void shouldGetNumericDateValue() {
        long seconds = 1476824844L;
        JsonNode value = writeContext.valueToTree(seconds);
        Claim claim = claimFromNode(value);

        assertThat(claim.asDate(), is(new Date(seconds * 1000)));
        assertThat(claim.asInstant(), is(Instant.ofEpochSecond(seconds)));
    }

    @Test
    public void shouldGetNullIfNotNumericDateValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asDate(), is(nullValue()));
        assertThat(claimFromNode(objectValue).asInstant(), is(nullValue()));
        JsonNode stringValue = writeContext.valueToTree("1476824844");
        assertThat(claimFromNode(stringValue).asDate(), is(nullValue()));
        assertThat(claimFromNode(stringValue).asInstant(), is(nullValue()));
    }

    @Test
    public void shouldGetStringValue() {
        JsonNode value = writeContext.valueToTree("string");
        Claim claim = claimFromNode(value);

        assertThat(claim.asString(), is(notNullValue()));
        assertThat(claim.asString(), is("string"));
    }

    @Test
    public void shouldGetNullStringIfNotStringValue() {
        JsonNode objectValue = writeContext.valueToTree(new Object());
        assertThat(claimFromNode(objectValue).asString(), is(nullValue()));
        JsonNode intValue = writeContext.valueToTree(12345);
        assertThat(claimFromNode(intValue).asString(), is(nullValue()));
    }

    @Test
    public void shouldGetArrayValueOfCustomClass() {
        JsonNode value = writeContext.valueToTree(new UserPojo[]{new UserPojo("George", 1), new UserPojo("Mark", 2)});
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(UserPojo.class), is(notNullValue()));
        assertThat(claim.asArray(UserPojo.class), is(arrayContaining(new UserPojo("George", 1), new UserPojo("Mark", 2))));
    }

    @Test
    public void shouldGetArrayValue() {
        JsonNode value = writeContext.valueToTree(new String[]{"string1", "string2"});
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(notNullValue()));
        assertThat(claim.asArray(String.class), is(arrayContaining("string1", "string2")));
    }

    @Test
    public void shouldGetNullArrayIfNullValue() {
        JsonNode value = writeContext.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayIfNonArrayValue() {
        JsonNode value = writeContext.valueToTree(1);
        Claim claim = claimFromNode(value);

        assertThat(claim.asArray(String.class), is(nullValue()));
    }

    @Test
    public void shouldThrowIfArrayClassMismatch() {
        JsonNode value = writeContext.valueToTree(new String[]{"keys", "values"});
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.asArray(UserPojo.class);
    }

    @Test
    public void shouldGetListValueOfCustomClass() {
        JsonNode value = writeContext.valueToTree(Arrays.asList(new UserPojo("George", 1), new UserPojo("Mark", 2)));
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(UserPojo.class), is(notNullValue()));
        assertThat(claim.asList(UserPojo.class), is(hasItems(new UserPojo("George", 1), new UserPojo("Mark", 2))));
    }

    @Test
    public void shouldGetListValue() {
        JsonNode value = writeContext.valueToTree(Arrays.asList("string1", "string2"));
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(notNullValue()));
        assertThat(claim.asList(String.class), is(hasItems("string1", "string2")));
    }

    @Test
    public void shouldGetNullListIfNullValue() {
        JsonNode value = writeContext.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(nullValue()));
    }

    @Test
    public void shouldGetNullListIfNonArrayValue() {
        JsonNode value = writeContext.valueToTree(1);
        Claim claim = claimFromNode(value);

        assertThat(claim.asList(String.class), is(nullValue()));
    }

    @Test
    public void shouldThrowIfListClassMismatch() {
        JsonNode value = writeContext.valueToTree(new String[]{"keys", "values"});
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.asList(UserPojo.class);
    }

    @Test
    public void shouldGetNullMapIfNullValue() {
        JsonNode value = writeContext.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim.asMap(), is(nullValue()));
    }

    @Test
    public void shouldGetNullMapIfNonArrayValue() {
        JsonNode value = writeContext.valueToTree(1);
        Claim claim = claimFromNode(value);

        assertThat(claim.asMap(), is(nullValue()));
    }

    @Test
    public void shouldGetMapValue() {
        Map<String, Object> map = new HashMap<>();
        map.put("text", "extraValue");
        map.put("number", 12);
        map.put("boolean", true);
        map.put("object", Collections.singletonMap("something", "else"));

        JsonNode value = writeContext.valueToTree(map);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        Map<String, Object> backMap = claim.asMap();
        assertThat(backMap, is(notNullValue()));
        assertThat(backMap, hasEntry("text", "extraValue"));
        assertThat(backMap, hasEntry("number", 12));
        assertThat(backMap, hasEntry("boolean", true));
        assertThat(backMap, hasKey("object"));
        assertThat((Map<String, Object>) backMap.get("object"), IsMapContaining.hasEntry("something", "else"));
    }

    @Test
    public void shouldThrowIfAnExtraordinaryExceptionHappensWhenParsingAsGenericMap() throws Exception {
        JsonNode value = mock(ObjectNode.class);
        when(value.getNodeType()).thenReturn(JsonNodeType.OBJECT);

        DeserializationContextExt mockedMapper = mock(DeserializationContextExt.class);

        JsonNodeClaim claim = (JsonNodeClaim) JsonNodeClaim.claimFromNode(value, mockedMapper);
        JsonNodeClaim spiedClaim = spy(claim);
        
        JsonParser mockedParser = mock(JsonParser.class);
        when(mockedMapper.treeAsTokens(value)).thenReturn(mockedParser);
        when(mockedParser.readValueAs(ArgumentMatchers.any(TypeReference.class))).thenThrow(JacksonException.class);

        exception.expect(JWTDecodeException.class);
        spiedClaim.asMap();
    }

    @Test
    public void shouldGetCustomClassValue() {
        JsonNode value = writeContext.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim.as(UserPojo.class).getName(), is("john"));
        assertThat(claim.as(UserPojo.class).getId(), is(123));
    }

    @Test
    public void shouldThrowIfCustomClassMismatch() {
        JsonNode value = writeContext.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);

        exception.expect(JWTDecodeException.class);
        claim.as(String.class);
    }

    @Test
    public void shouldReturnNullForMissingAndNullClaims() {
        JsonNode missingValue = MissingNode.getInstance();
        Claim missingClaim = claimFromNode(missingValue);
        assertThat(missingClaim.isMissing(), is(true));
        assertThat(missingClaim.isNull(), is(false));
        assertNull(missingClaim.as(String.class));
        assertNull(missingClaim.asString());
        assertNull(missingClaim.asBoolean());
        assertNull(missingClaim.asDate());
        assertNull(missingClaim.asDouble());
        assertNull(missingClaim.asLong());
        assertNull(missingClaim.asInt());
        assertNull(missingClaim.asInstant());
        assertNull(missingClaim.asMap());
        assertNull(missingClaim.asList(String.class));
        assertNull(missingClaim.asArray(String.class));

        JsonNode nullValue = writeContext.valueToTree(null);
        Claim nullClaim = claimFromNode(nullValue);
        assertThat(nullClaim.isMissing(), is(false));
        assertThat(nullClaim.isNull(), is(true));
        assertNull(nullClaim.as(String.class));
        assertNull(nullClaim.asString());
        assertNull(nullClaim.asBoolean());
        assertNull(nullClaim.asDate());
        assertNull(nullClaim.asDouble());
        assertNull(nullClaim.asLong());
        assertNull(nullClaim.asInt());
        assertNull(nullClaim.asInstant());
        assertNull(nullClaim.asMap());
        assertNull(nullClaim.asList(String.class));
        assertNull(nullClaim.asArray(String.class));
    }

    @Test
    public void shouldReturnNullForInvalidArrayValue() {
        JsonNode value = writeContext.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);
        assertNull(claim.asArray(String.class));
    }

    @SuppressWarnings({"unchecked", "RedundantCast"})
    @Test
    public void shouldGetAsMapValue() {
        JsonNode value = writeContext.valueToTree(Collections.singletonMap("key", new UserPojo("john", 123)));
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        Map map = claim.as(Map.class);
        assertThat(((Map<String, Object>) map.get("key")), hasEntry("name", (Object) "john"));
        assertThat(((Map<String, Object>) map.get("key")), hasEntry("id", (Object) 123));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingMissingNode() {
        JsonNode value = MissingNode.getInstance();
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim.isMissing(), is(true));
        assertThat(claim.isNull(), is(false));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingNullNode() {
        JsonNode value = NullNode.getInstance();
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim.isNull(), is(true));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnBaseClaimWhenParsingNullValue() {
        JsonNode value = writeContext.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim.isNull(), is(true));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingObject() {
        JsonNode value = writeContext.valueToTree(new Object());
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingArray() {
        JsonNode value = writeContext.valueToTree(new String[]{});
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingList() {
        JsonNode value = writeContext.valueToTree(new ArrayList<String>());
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingStringValue() {
        JsonNode value = writeContext.valueToTree("");
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingIntValue() {
        JsonNode value = writeContext.valueToTree(Integer.MAX_VALUE);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingDoubleValue() {
        JsonNode value = writeContext.valueToTree(Double.MAX_VALUE);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingDateValue() {
        JsonNode value = writeContext.valueToTree(new Date());
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNonNullClaimWhenParsingBooleanValue() {
        JsonNode value = writeContext.valueToTree(Boolean.TRUE);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(false));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldReturnNullIsTrue() {
        JsonNode value = writeContext.valueToTree(null);
        Claim claim = claimFromNode(value);

        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(JsonNodeClaim.class)));
        assertThat(claim.isNull(), is(true));
        assertThat(claim.isMissing(), is(false));
    }

    @Test
    public void shouldDelegateToJsonNodeToString() {
        JsonNode value = writeContext.valueToTree(new UserPojo("john", 123));
        Claim claim = claimFromNode(value);
        assertThat(claim.toString(), is(value.toString()));
    }

    @Test
    public void shouldConvertToString() {
        JsonNode value = writeContext.valueToTree(new UserPojo("john", 123));
        JsonNode nullValue = writeContext.valueToTree(null);
        JsonNode missingValue = MissingNode.getInstance();

        Claim claim = claimFromNode(value);
        Claim nullClaim = claimFromNode(nullValue);
        Claim missingClaim = claimFromNode(missingValue);

        assertThat(claim.toString(), is("{\"id\":123,\"name\":\"john\"}"));
        assertThat(nullClaim.isNull(), is(true));
        assertThat(nullClaim.toString(), is("Null claim"));
        assertThat(missingClaim.isMissing(), is(true));
        assertThat(missingClaim.toString(), is("Missing claim"));

    }
}