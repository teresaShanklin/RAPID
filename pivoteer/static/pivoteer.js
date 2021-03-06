// Queue handler for ajax requests
ajax_handler = [];

// Abort any unfinished ajax requests
function kill_ajax() {
    $.each(ajax_handler, function( index, value ) { value.abort() });
    ajax_handler.length = 0;
}


// Submit for all records
function run_records(form_data) {

    var records = [ "current", "passive", "malware", "other"];

    $.each(records, function( index, record ) {
        // Clear out old information from DOM elements and submit new ajax requests
        $(record).empty();

        // Push additional form data to differentiate ajax requests
        form_data.push({name: 'record_type', value: record});

        send_ajax(form_data, record);

        // Pop off additional form data to in preparation for next request
        form_data.pop();
    });
}


// Submit request for record
function send_ajax(form_data, record){

    var record_element = "#" + record;

    ajax_handler.push(
        $.ajax({
            type:"POST",
            url:"/pivoteer/",
            data: form_data,
            beforeSend: function(xhr, settings) {
                $(record_element).html("Retrieving data");
            },

            error: function (){
                $( record_element ).html('Unable to retrieve records')
            },

            success: function (task){
                if (task.errors) {
                    $( record_element ).html(task.errors.indicator);
                } else {
                    poll_ajax(task.id, record_element);
                }
            }
        })
    );
}


// Poll for record completion
function poll_ajax(task, record_element){

    var parameters = {task_id: task};

    $.ajax({
        type:"POST",
        url:"/pivoteer/tasks/",
        data: parameters,

        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        },

        error: function (){
            $(record_element).html("Unable to retrieve records");
        },

        success: function (task_results){
            if (task_results.status == 'loading') {
                setTimeout(function() { poll_ajax(task, record_element); }, 6000); // wait 3 seconds then call ajax request again
            } else {
                $(record_element).html(task_results);
                initialize_table(record_element);
            }
        }
    });
}


// Initiate data table elements on returned records
function initialize_table(record_element) {

    if (record_element == '#current') {
        $('#CR_table').dataTable({
            "iDisplayLength":  15,
            "info":            false,
            "bLengthChange":   false,
            "bFilter":         false
        });

    } else if (record_element == "#passive") {
        $('#PR_table').dataTable({
            "iDisplayLength":  15,
            "info":            false,
            "bLengthChange":   false
        });

    } else if (record_element == "#malware") {
        $('#MR_table').dataTable({
            "iDisplayLength":  15,
            "info":            false,
            "bLengthChange":   false
        });

    } else if (record_element == "#other") {
        $('#OR_table').dataTable({
            "paging":          false,
            "info":            false,
            "bLengthChange":   false,
            "bFilter":         false
        });
    }
}


// Cookie Handling Using jQuery
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

var csrftoken = getCookie('csrftoken');
// End Cookie Handling


// Custom method on form submission to begin research
$('#research_indicator').submit(function( event ){
    event.preventDefault();
    kill_ajax();

    $(".panel").show();

    // Populate data for ajax and DOM manipulation
    var entry = $('input[name=indicator]').val();
    var form_data = $('#research_indicator').serializeArray();

    // Clear out pivot navigation menu and insert new initial entry
    $("#pivot_navigator").empty().append("<li><span class='pivot tracking'>" + entry + "</span></li>");

    run_records(form_data);
});


$('#content').on('click', '.pivot', function( event ){
    kill_ajax();

    var pivot = $(this).text();
    var pivot_data = [{name: "indicator", value: pivot}, {name: "csrfmiddlewaretoken", value: csrftoken}];

    // Check if this is a back pivot or a new pivot
    if ($(this).hasClass('tracking')){
        $( '.pivot' ).parent().slice($(this).parent().index() + 1).remove();
    }
    else {
        $("#pivot_navigator").append("<li><span class='pivot tracking'>" + pivot + "</span></li>");
    }

    run_records(pivot_data);
});


// Differentiate exports and send request to server
$(document).on('click', '.export', function( event ){

    var indicator = $("#pivot_navigator span:last").text();
    var record_type = $(this).attr('data-export-type');

    $('#export_type').val(record_type);
    $('#export_indicator').val(indicator);
    $('#export').submit();
});


// Manipulate displayed elements upon initial page load
$( document ).ready(function() {
    $(".panel").hide();
});