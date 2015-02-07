$( document ).ready(function() {

    $('#monitor_table').dataTable({
            "iDisplayLength":  25,
            "info":            false,
            "bLengthChange":   false
    });

    $('#alert_table').dataTable({
            "iDisplayLength":  25,
            "info":            false,
            "bLengthChange":   false,
            "bFilter":         false
    });
});
