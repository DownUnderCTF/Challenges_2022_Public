#include <nana/gui.hpp>
#include <nana/gui/widgets/button.hpp>
#include <nana/gui/widgets/menubar.hpp>
#include <nana/gui/filebox.hpp>

#include <iostream>
#include <filesystem>
#include <fstream>

const int CANVAS_SIZE = 512;
const int WINDOW_MARGIN = 16;
const int TOP_MARGIN = 16;
const int PICKER_SIZE = (CANVAS_SIZE - WINDOW_MARGIN * 7) / 8;
const nana::color CANVAS_COLOURS[] = {
	nana::colors::white,
	nana::colors::silver,
	nana::colors::black,
	nana::colors::red,
	nana::colors::green,
	nana::colors::blue,
	nana::colors::yellow,
	nana::colors::purple,
};
const int TOT_PIXELS = (CANVAS_SIZE / 8) * (CANVAS_SIZE / 8);

nana::color current_draw_color = CANVAS_COLOURS[0];
nana::color current_draw_instructions[CANVAS_SIZE / 8][CANVAS_SIZE / 8]; 

int packcolor(nana::color color) {
	if (color == nana::colors::white) return 0;
	if (color == nana::colors::silver) return 1;
	if (color == nana::colors::black) return 2;
	if (color == nana::colors::red) return 3;
	if (color == nana::colors::green) return 4;
	if (color == nana::colors::blue) return 5;
	if (color == nana::colors::yellow) return 6;
	if (color == nana::colors::purple) return 7;
	return -1;
}

int oddbits(int n) {
	n = ((n & 0x44444444) >> 1) | (n & 0x11111111);
	n = ((n & 0x30303030) >> 2) | (n & 0x03030303);
	n = ((n & 0x0F000F00) >> 4) | (n & 0x000F000F);
	n = ((n & 0x00FF0000) >> 8) | (n & 0x000000FF);
  	return n;
}

int main() {

	for (int y = 0; y < CANVAS_SIZE / 8; y++) {
		for (int x = 0 ; x < CANVAS_SIZE / 8; x++) {
			current_draw_instructions[y][x] = nana::colors::white;
		}
	}

	nana::form fm(nana::API::make_center(CANVAS_SIZE + WINDOW_MARGIN*2, CANVAS_SIZE + WINDOW_MARGIN*3 + PICKER_SIZE + TOP_MARGIN));\
	fm.caption("Artisan Paint Tool");

	nana::drawing dw(fm);
	dw.draw([](nana::paint::graphics& graph){
        for (int y = 0; y < CANVAS_SIZE / 8; y++) {
			for (int x = 0 ; x < CANVAS_SIZE / 8; x++) {
				graph.rectangle(
					nana::rectangle{WINDOW_MARGIN + x * 8, TOP_MARGIN + WINDOW_MARGIN + y * 8, 8, 8},
        			true,
        			current_draw_instructions[y][x]
				);
			}
		}
    });

    fm.events().mouse_move([&dw](const nana::arg_mouse&arg){
    	int x = arg.pos.x;
    	int y = arg.pos.y;
    	// In canvas and clicked?
    	if (!arg.left_button) return;
    	if (x < WINDOW_MARGIN || x >= CANVAS_SIZE + WINDOW_MARGIN) return;
    	if (y < TOP_MARGIN + WINDOW_MARGIN || y >= CANVAS_SIZE + WINDOW_MARGIN + TOP_MARGIN) return;

    	// Make relative to canvas
    	x -= WINDOW_MARGIN;
    	y -= WINDOW_MARGIN + TOP_MARGIN;
    	x /= 8;
    	y /= 8;

    	current_draw_instructions[y][x] = current_draw_color;

    	dw.update();
    });

    std::vector<std::unique_ptr<nana::button>> buttons;

    for (int i = 0; i < 8; i++) {
    	buttons.emplace_back(
    		new nana::button(fm, nana::rectangle(
    			WINDOW_MARGIN + (PICKER_SIZE + WINDOW_MARGIN)*i,
    			CANVAS_SIZE + WINDOW_MARGIN*2 + TOP_MARGIN,
    			PICKER_SIZE,
    			PICKER_SIZE)
    		)
    	);
    	buttons.back()->bgcolor(CANVAS_COLOURS[i]);
    	buttons.back()->events().click([i]{
    		current_draw_color = CANVAS_COLOURS[i];
    	});
    }

    nana::menubar mn(fm);
    mn.push_back("File");
    mn.at(0).append("Save", [&fm](nana::menu::item_proxy& ip)
    {
        nana::filebox picker{nullptr, false};
        auto paths = picker.show();
        if (paths.empty()) return;
        auto path = paths.front();

        int tmp = 0;
        std::vector<unsigned char> v;

        // Step 1: Pack the pixels like 0b00xxxyyy in z order traversal
        for (int n = 0; n < TOT_PIXELS; n++) {
        	int x = oddbits(n);
        	int y = oddbits(n >> 1);
        	tmp <<= 3;
        	tmp |= packcolor(current_draw_instructions[y][x]);
        	if (n % 2 == 0) continue;
        	v.push_back(tmp);
        	tmp = 0;
        }

        // Step 2: Compress with custom LZ77 scheme
        // form: 0b00xxxxxx : literal
        // otherwise: compressed byte 0b1aaaaabb
        // a+3 len
        // b back
        std::vector<unsigned char> vv;
        for (int n = 0; n < v.size();) {
        	// O(n^2) lol
        	int saved_len = 0;
        	int saved_off = 0;
        	for (int m = std::min(std::min(34, n), static_cast<int>(v.size() - n)); m >= 3; m--) {
        		auto fwd_slice = std::vector<unsigned char>(v.begin() + n, v.begin() + n + m);
        		for (int off = n - m; off >= std::max(0, n - m - 3); off--) {
        			auto bkwd_slice = std::vector<unsigned char>(v.begin() + off, v.begin() + off + m);
        			if (fwd_slice == bkwd_slice) {
        				saved_len = m;
        				saved_off = n - off - m;
        				goto done;
        			}
        		}
        	}
        	done:
        	if (saved_len) {
        		vv.push_back(static_cast<unsigned char>((1 << 7) | ((saved_len-3) << 2) | saved_off));
        		n += saved_len;
        	}
        	else {
        		vv.push_back(v[n]);
        		n += 1;
        	}
        }

        std::ofstream file(path);
        std::copy(vv.cbegin(), vv.cend(), std::ostreambuf_iterator<char>(file));
        file.close();
    });


	fm.show();
	nana::exec();
}