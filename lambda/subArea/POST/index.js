const AWS = require("aws-sdk");
const {
  dynamodb,
  TABLE_NAME,
  incrementAndGetNextSubAreaID,
  getOne,
} = require("../../dynamoUtil");
const { createKeycloakRole } = require("../../keycloakUtil");
const { sendResponse } = require("../../responseUtil");
const { decodeJWT, resolvePermissions } = require("../../permissionUtil");
const { logger } = require("../../logger");
const { getValidSubareaObj } = require("../../subAreaUtils");

const SSO_URL = process.env.SSO_URL || "https://dev.loginproxy.gov.bc.ca";
const SSO_CLIENT_ID = process.env.SSO_CLIENT_ID || "attendance-and-revenue";

exports.handler = async (event, context) => {
  logger.debug("Subarea POST:", event);
  return await main(event, context);
};

async function main(event, context) {
  try {
    const token = await decodeJWT(event);
    const permissionObject = resolvePermissions(token);

    if (!permissionObject.isAuthenticated) {
      logger.info("**NOT AUTHENTICATED, PUBLIC**");
      return sendResponse(403, { msg: "Error: Unauthenticated." }, context);
    }

    // Admins only
    if (!permissionObject.isAdmin) {
      logger.info("Not authorized.");
      return sendResponse(403, { msg: "Unauthorized." }, context);
    }

    const body = JSON.parse(event.body);

    // ensure all madatory fields exist
    if (
      !body.orcs ||
      !body.activities ||
      !body.managementArea ||
      !body.section ||
      !body.region ||
      !body.bundle ||
      !body.subAreaName
    ) {
      return sendResponse(400, { msg: "Invalid body" }, context);
    }

    // Get park
    const park = getOne("park", body.orcs);
    if (!park) {
      logger.debug("Unable to find park", body.orcs);
      return sendResponse(400, { msg: "Park not found" }, context);
    }

    // Remove bad fields
    let obj = getValidSubareaObj(body, park.parkName);

    // Add roles
    obj.roles = ["sysadmin", body.orcs];

    // Generate subArea id
    const subAreaId = await incrementAndGetNextSubAreaID();

    // Create transaction
    let transactionObj = { TransactItems: [] };

    //// Create entry obj for park
    const subAreaEntry = {
      name: obj.subAreaName,
      id: subAreaId,
    };

    //// Create update park obj
    const updatePark = {
      TableName: TABLE_NAME,
      Key: {
        pk: { S: "park" },
        sk: { S: obj.orcs },
      },
      ExpressionAttributeValues: {
        ":newSubArea": {
          L: [{ M: AWS.DynamoDB.Converter.marshall(subAreaEntry) }],
        },
        ":empty_list": { L: [] },
      },
      UpdateExpression:
        "subAreas = list_append(if_not_exists(subAreas, :empty_list), :newSubArea)",
    };
    transactionObj.TransactItems.push({
      Update: updatePark,
    });

    // Create subArea
    const putSubArea = {
      TableName: TABLE_NAME,
      ConditionExpression: "attribute_not_exists(sk)",
      Item: {
        pk: { S: `park::${obj.orcs}` },
        sk: { S: subAreaId },
        activities: { SS: obj.activities },
        managementArea: { S: obj.managementArea },
        section: { S: obj.section },
        region: { S: obj.region },
        bundle: { S: obj.bundle },
        subAreaName: { S: obj.subAreaName },
      },
    };
    transactionObj.TransactItems.push({
      Put: putSubArea,
    });

    const res = await dynamodb.transactWriteItems(transactionObj).promise();
    logger.debug("res:", res);

    // Add Keycloak role
    const kcRes = await createKeycloakRole(
      SSO_URL,
      SSO_CLIENT_ID,
      token,
      `${obj.orcs}::${subAreaId}`,
      `${park.parkName}:${obj.subAreaName}`
    );
    logger.debug("kcRes:", kcRes);

    return sendResponse(200, { msg: "Subarea created", subArea: res }, context);
  } catch (err) {
    logger.error(err);
    return sendResponse(400, { msg: "Invalid request" }, context);
  }
}
