public enum PayloadTypes {
    UTF("utf"),
    INT("int"),
    BYTES("bytes");

    private final String dataType;

    PayloadTypes(String dataType) {
        this.dataType = dataType;
    }

    public String getDataType() {
        return dataType;
    }

    public static PayloadTypes fromString(String text) {
        for (PayloadTypes dataEnum : PayloadTypes.values()) {
            if (dataEnum.getDataType().equalsIgnoreCase(text)) {
                return dataEnum;
            }
        }
        throw new IllegalArgumentException("Invalid data type: " + text);
    }
}
