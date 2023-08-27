module com.stegodocx {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;

    opens com.stegodocx to javafx.fxml;
    exports com.stegodocx;
}