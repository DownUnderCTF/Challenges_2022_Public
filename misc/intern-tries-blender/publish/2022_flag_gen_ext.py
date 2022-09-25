import bpy

# Hey buddy, Pix here, this should set you up with some basic info
# just set up the extensions and let it gen <3

bl_info = {
    "name": "DUCTF Flag Generator!",
    "author": "Pix",
    "version": (1, 0),
    "blender": (3, 20, 0),
    "location": "View3D > Sidebar > DUCTF > Gen Flag",
    "description": "Generates a new flag! :>",
    "warning": "",
    "doc_url": "",
    "category": "Add Flag",
}

class ductf_panel_ext(bpy.types.Panel):
    bl_label = "DUCTF Flag Generator!"
    bl_idname = "OBJECT_PT_ductf_panel"
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_category = "DUCTF"

    def draw(self, context):
        layout = self.layout
        row = layout.row()
        row = layout.row()
        row.label(text =  "Click to Generate the flag!")
        row = layout.row()
        row = layout.row()
        row = layout.split(factor = 0.45)
        row.label(text = "")
        row.operator("wm.ductf_flag_op", text="Gen Flag", icon = "OUTLINER_OB_FONT")

class wm_ot_text_op(bpy.types.Operator):
    bl_label = "Flag Gen: Choose the right options!"
    bl_idname = "wm.ductf_flag_op"
    
    a : bpy.props.BoolProperty(name = "Make flag", default = False)
    b : bpy.props.BoolProperty(name = "Make flag 2", default = False)
    c : bpy.props.BoolProperty(name = "Make flag for real", default = False)
    d : bpy.props.BoolProperty(name = "Final Flag make", default = False)
    e : bpy.props.BoolProperty(name = "FinalFinal Flag make", default = False)
    f : bpy.props.BoolProperty(name = "WORK DAMNIT", default = False)
    g : bpy.props.BoolProperty(name = "PLEASEPUTTHEFLAG", default = False)
    h : bpy.props.BoolProperty(name = "Attempt 17", default = False)
    i : bpy.props.BoolProperty(name = "Working! ", default = False)
    j : bpy.props.BoolProperty(name = "Working Better", default = False)
    k : bpy.props.BoolProperty(name = "Whats git?", default = False)
    l : bpy.props.BoolProperty(name = "2021 Flag Working Version", default = False)
    m : bpy.props.BoolProperty(name = "Marketing version", default = False)
    n : bpy.props.BoolProperty(name = "Flag4DUCTF", default = False)
    o : bpy.props.BoolProperty(name = "Flag4DUCTF2", default = False)
    p : bpy.props.BoolProperty(name = "Flag4DUCTF3", default = False)
    q : bpy.props.BoolProperty(name = "__main_flag_make__", default = False)
    r : bpy.props.BoolProperty(name = "Shoulda used Cura.jpg", default = False)
    s : bpy.props.BoolProperty(name = "Make Flag 4", default = False)
    t : bpy.props.BoolProperty(name = "Make Flag 3", default = False)
    u : bpy.props.BoolProperty(name = "Duplicates Flag", default = False)
    v : bpy.props.BoolProperty(name = "Breaks Flag", default = False)
    w : bpy.props.BoolProperty(name = "Solves Flag", default = False)
    x : bpy.props.BoolProperty(name = "Deletes Flag", default = False)
    y : bpy.props.BoolProperty(name = "Compiles Flag", default = False)
    z : bpy.props.BoolProperty(name = "MesonFlagGenratorForRealDoe", default = False)
    
    def execute(self, context):
        a = self.a
        b = self.b
        c = self.c
        d = self.d
        e = self.e
        f = self.f
        g = self.g
        h = self.h
        i = self.i
        j = self.j
        k = self.k
        l = self.l
        m = self.m
        n = self.n
        o = self.o
        p = self.p
        q = self.q
        r = self.r
        s = self.s
        t = self.t
        u = self.u
        v = self.v
        w = self.w
        x = self.x
        y = self.y
        z = self.z   
        
        if a == True: # Obviously the First and last options make the most sense.
            if u == False:
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="CTFDU{AFLag?!ADN<3)")
                bpy.ops.object.editmode_toggle()
                bpy.ops.transform.rotate(value=-1.01692, orient_axis='Z', orient_type='VIEW', orient_matrix=((0.9995, -0.0313888, -0.00377347), (0.0312973, 0.999262, -0.0222778), (0.00446996, 0.0221486, 0.999745)), orient_matrix_type='VIEW', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False)
                bpy.ops.transform.translate(value=(6.07794, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.context.object.data.extrude = -2.0
                bpy.ops.transform.trackball(value=(0.38, -0.23), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            else:
                print("Undo :>")
            if z == True:
                print("TODO: Write the flag here")
        if b == True:
            bpy.ops.mesh.primitive_plane_add(size=2, enter_editmode=False, align='WORLD', location=(12.1036, -3.65543, 0.18712), scale=(1, 1, 1))
            bpy.ops.transform.rotate(value=-0.959123, orient_axis='Z', orient_type='VIEW', orient_matrix=((0.982876, -0.18424, -0.00341157), (0.182441, 0.970347, 0.158562), (-0.025903, -0.156469, 0.987343)), orient_matrix_type='VIEW', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False)
            bpy.ops.transform.resize(value=(1, 8.92112, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-2.18673, 3.97614, 1.33615), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(5.87845, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(1.56723, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(2.39681, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="N0$SFlaGHaer}")
            bpy.ops.object.editmode_toggle()
        if c == True:  # This should reveal a new option
            bpy.ops.mesh.primitive_cone_add(radius1=1, radius2=0, depth=2, enter_editmode=False, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(0, 1.93324, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(0.47, -0.33), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 1, -12.5448), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(0.61, 0.82), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if b == True: # Unless...
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text=" tn p3n Kal1:: {-{-{")
                bpy.ops.object.editmode_toggle()
        if d == True:
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="<GN11NDImUrhZFoWnd")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(0, 1.93324, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(0.47, -0.33), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 1, -12.5448), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(0.61, 0.82), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.extrude = 0.8
            if b == True:
                bpy.context.object.data.space_character = 5.5
        if e == True: # E 
            bpy.ops.object.text_add(enter_editmode=True, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="CTF{M4bvyeF_)G")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(12.1185, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.rotate(value=3.13171, orient_axis='Z', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(0, 0.492172, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if x == True: # for combining the flag!
                bpy.ops.object.text_add(enter_editmode=True, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="DU La  4U2Ch4ck}")
                bpy.ops.object.editmode_toggle()
                bpy.ops.mesh.primitive_circle_add(radius=1, enter_editmode=False, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
                bpy.ops.transform.translate(value=(6.32399, -4.22207, -0.527532), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(4.79287, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                if u == True:
                    print("Debug mode is so hard to find aaaaaaa")
        if f == True: # F for flag is probably too obvious.. or maybe a double bluff?!
            bpy.ops.object.text_add(enter_editmode=True, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DU{CT\\}F05DL337H45kcerG")
            bpy.ops.object.editmode_toggle()
            bpy.context.object.data.extrude = 1.4
            bpy.ops.transform.rotate(value=1.08947, orient_axis='Y', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False)
            bpy.ops.transform.rotate(value=-1.91621, orient_axis='Z', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False)
        if g == True: # G G ; - ;
            if q == False: # Q Q
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="B wW z n0  TA;  URST")
                bpy.ops.object.editmode_toggle()
            else:
                bpy.ops.surface.primitive_nurbs_surface_cylinder_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.trackball(value=(0.27, 1.78), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(19.3581, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.surface.primitive_nurbs_surface_cylinder_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.trackball(value=(0.27, 1.78), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(19.3581, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(7.08317, 5.88189, 1.57948), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.surface.primitive_nurbs_surface_cylinder_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.trackball(value=(0.27, 1.78), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(19.3581, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.trackball(value=(1.24, -1.5), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.trackball(value=(0.08, 0.25), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(4.44521, 1.81602, 0.286283), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if h == True:
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="F0E T 4HgCXUS")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(3.06729, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.space_character = 3.7
            bpy.context.object.data.extrude = 0.8
            bpy.context.object.data.space_word = 0.1
            bpy.ops.mesh.primitive_cube_add(enter_editmode=False, align='WORLD', location=(0.174783, 0.209367, 0.216415), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(0, 24.7161, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if i == True:
            bpy.ops.mesh.primitive_torus_add(align='WORLD', location=(0.128029, 0.0699902, -0.000379562), rotation=(0, 0, 0), major_radius=1, minor_radius=0.25, abso_major_rad=1.25, abso_minor_rad=0.75)
            bpy.ops.transform.trackball(value=(-3.13, 1.5), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(3.5519, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1.88869, 1.88869, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.mesh.primitive_torus_add(align='WORLD', location=(0.128029, 0.0699902, -0.000379562), rotation=(0, 0, 0))
            bpy.ops.transform.resize(value=(1.20267, 1, 1.20267), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(12.8426, -1.0837, 1.34005), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(0.89, -1.14), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.mesh.primitive_torus_add(align='WORLD', location=(0.128029, 0.0699902, -0.000379562), rotation=(0, 0, 0))
            bpy.ops.transform.rotate(value=-0.625213, orient_axis='Y', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 1.94228, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 1.28067, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 2.29496, 2.29496), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(8.47912, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if j == True:
            bpy.ops.mesh.primitive_plane_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.trackball(value=(-0.2, 1.09), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(5.97192, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 2.90888, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(15.9995, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if h == True:
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="L0E A 4HXCXBS")
                bpy.ops.object.editmode_toggle()
                bpy.context.object.data.space_character = 3.7
                bpy.context.object.data.extrude = 0.8
                bpy.context.object.data.space_word = 0.1
            bpy.ops.surface.primitive_nurbs_surface_surface_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.resize(value=(18.8624, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-3.74376, -0, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if k == True:
            bpy.ops.object.speaker_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(7.78029, -3.45678, -1.29444), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if u == True:
                print("Undo everything :>")
        if l == True:
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="ADBUCCDTEF}-")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(-17.8816, -0, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.space_character = 0.1
            bpy.context.object.data.space_word = 0.9
        if m == True: # MONKEY MANIA
            bpy.ops.mesh.primitive_monkey_add(size=2, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.context.object.scale[0] = 80
            bpy.context.object.scale[1] = 80
            bpy.context.object.scale[2] = 80
            print("TODO: Make monkey speak the flag!")
        if n == True:
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="C wr x noE  TADRST")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(1.54608, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.space_character = 2.5
            bpy.context.object.data.space_word = 0.4
            bpy.ops.mesh.primitive_plane_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(8.12638, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(3.73098, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-0, -0, -2.68493), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if o == True:
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(0.128029, 0.0699902, -0.000379562), rotation=(0.431507, 0.00018319, -0.0819906), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(14.3984, 4.32364, 2.52458), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(2.6, -3.37), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="(F  G  H  E  e h e h e )nwgmnju49hi^H9s HH sthr)")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(9.79805, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(0, 1.91847, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if p == True: # PENGUIN!
            # PRINT
            up = 0
            while up < 20:
                bpy.ops.mesh.primitive_cube_add(enter_editmode=False, align='WORLD', location=(0.128029, up, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(23.58, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1.3335, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(28.9753, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                up += 1
        if q == True: # Maybe is should be 30.. Heck.
            pix = -60
            while pix < 60:
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(pix, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(0, pix, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(0, 0, pix), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(pix, pix, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(pix, 0, pix), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.armature_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.resize(value=(9.34436, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 1, 8.49155), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(0, pix, pix), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)           
                pix += 4
        if r == True: # Hmm... broken?
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="GN AYn FTF 4GG  F-4 ROnp   Demkk")
            bpy.ops.object.editmode_toggle()
            bpy.ops.transform.translate(value=(0, 0, 1.25154), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.space_character = 0.0
            bpy.context.object.data.space_word = 6.3
            bpy.context.object.data.extrude = 2.8
        if s == True:
            bpy.ops.object.text_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.rotate(value=1.05287, orient_axis='Y', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False)
            bpy.context.object.data.size = 10
            bpy.context.object.data.extrude = 2.8
            bpy.ops.object.text_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.resize(value=(3.54666, 3.54666, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 5.4319, 5.4319), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-0.330667, 0.792333), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-12.4435, -0, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.context.object.data.extrude = 6.8
        if t == True: # You think they'll let me work at DUCTF after I make a cool flag?
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="U{SeNr")
            if i == True:
                bpy.ops.font.text_insert(text="<Fl4g")
                bpy.ops.object.editmode_toggle()
            else:
                bpy.ops.object.editmode_toggle()
                bpy.ops.transform.translate(value=(0.818291, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.context.object.data.extrude = 0.2
                bpy.context.object.data.space_character = 5.2
        if u == True:
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(4, 4, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(8, 8, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(12, 12, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 16, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(4, 20, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(8, 24, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(12, 28, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 32, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF DUCTF BEST CTF")
            bpy.ops.object.editmode_toggle()
        if v == True: # Views amiright? Maybe you have to view it from the right angle and choose the right options..
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(32.4125, -45.7945, 5.89946), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1.14, -2.67605, 4.818789), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(161.146413, -2.67605, 616.34), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1.14413, 2.1605, 616.4), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1.53, -2.6, 616.345), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(5.14413, -6.12, 616.818789), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1231.113, -2.67605, 616.5), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(-51.16, -2.54, 616.818789), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(-1.145313, -2.3535, 616.818789), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(81.1443413, -2.643, -11.818789), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
        if w == True: # Flags are hard man...
            bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 0, 0), scale=(1, 1, 1))
            bpy.ops.font.delete(type="PREVIOUS_WORD")
            bpy.ops.font.text_insert(text="DT tTiv}rta  tnina h4rd A 3F")
            if v == True: # If view is right~
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="FTCUD :> D: S!")
            bpy.ops.object.editmode_toggle()
            bpy.context.object.data.extrude = 0.4
            bpy.context.object.data.space_character = 4.2
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(161.146413, -2.67605, 616.34), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1.14413, 2.1605, 616.4), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.object.camera_add(enter_editmode=False, align='VIEW', location=(1.53, -2.6, 616.345), rotation=(0.983029, 0.00113334, 0.386331), scale=(1, 1, 1))
            bpy.ops.surface.primitive_nurbs_surface_surface_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.trackball(value=(0.91, -0.53), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 7.58444, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-0.94, 0.77), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if x == True:
            if b == True:
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 5, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="DT tTiv}rta");
                bpy.ops.object.editmode_toggle()
            bpy.ops.object.metaball_add(type='CAPSULE', enter_editmode=False, align='WORLD', location=(1.14413, -2.67605, 0.818789), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(4.57737, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-1.78, -0.73), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-0.61, 0.04), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(0, 4.79146, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 3.49428, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.object.metaball_add(type='ELLIPSOID', enter_editmode=False, align='WORLD', location=(1.14413, -2.67605, 0.818789), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(24.2318, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(1, 1, 3.77573), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(2.40059, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-1.66, -0.12), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.surface.primitive_nurbs_surface_surface_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.trackball(value=(-0.48, 1.1), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(15.388, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.object.metaball_add(type='CUBE', enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.resize(value=(1, 7.23765, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(2.5025, 1, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-1.53, -1.09), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(8.4469, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if y == True: # Compiling the flag?!
            bpy.ops.surface.primitive_nurbs_surface_torus_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(6.45956, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if a == True:
                bpy.ops.surface.primitive_nurbs_surface_torus_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.translate(value=(1.56408, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.resize(value=(1, 3.84587, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if b == True:
                bpy.ops.surface.primitive_nurbs_surface_torus_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.translate(value=(6.45956, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if e == True and d == False:
                bpy.ops.surface.primitive_nurbs_surface_torus_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
                bpy.ops.transform.translate(value=(-2.6632, -0, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 5, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="GALF }TFUCD{");
                bpy.ops.object.editmode_toggle()
                bpy.context.object.data.extrude = 0.2
                bpy.context.object.data.space_word = 1.0
                bpy.ops.transform.rotate(value=3.22467, orient_axis='Y', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.ops.transform.translate(value=(7.61573, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
        if z == True: # Last one always perfect option :>
            bpy.ops.object.speaker_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.translate(value=(5.99657, 4.68109, 2.37332), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.mesh.primitive_uv_sphere_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.trackball(value=(1.12, 1.92), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(3.35062, 3.35062, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-0.52, 0.64), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(19.1051, 0, 0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, False, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.mesh.primitive_uv_sphere_add(radius=1, enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.trackball(value=(1.12, 1.92), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.resize(value=(3.35062, 3.35062, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.trackball(value=(-1.24, 1.11), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(6.2982, 2.86338, 1.55044), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.mesh.primitive_uv_sphere_add(enter_editmode=False, align='WORLD', location=(0.128029, 0.0699902, -0.000379562), scale=(1, 1, 1))
            bpy.ops.transform.resize(value=(4.58045, 4.58045, 1), orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(True, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(9.65937, -0.744783, -0.425692), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-0, -6.55147, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            bpy.ops.transform.translate(value=(-0, -0, -11.5454), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, False, True), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
            if a == True: # Together forevarrr
                bpy.ops.object.text_add(enter_editmode=True, align="WORLD", location=(0, 5, 0), scale=(1, 1, 1))
                bpy.ops.font.delete(type="PREVIOUS_WORD")
                bpy.ops.font.text_insert(text="o ; ^* 88 #ndu A A MK KKKD U DUCTFFF");
                bpy.ops.object.editmode_toggle()
                bpy.ops.transform.translate(value=(-0, -17.9015, -0), orient_axis_ortho='X', orient_type='GLOBAL', orient_matrix=((1, 0, 0), (0, 1, 0), (0, 0, 1)), orient_matrix_type='GLOBAL', constraint_axis=(False, True, False), mirror=False, use_proportional_edit=False, proportional_edit_falloff='SMOOTH', proportional_size=1, use_proportional_connected=False, use_proportional_projected=False, release_confirm=True)
                bpy.context.object.data.resolution_u = 64
                bpy.context.object.data.size = 4.14
        return {'FINISHED'}
    
    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self)

class OBJECT_PT_Spacing(bpy.types.Panel):
    bl_label = "Spacing"
    bl_idname = "OBJECT_PT_spacing"
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_category = "Text Tool"
    bl_parentid = "OBJECT_PT_texttool"
    bl_options = {"DEFAULT_CLOSED"}
    
    def draw(self, context):
        layout = self.layout
        text = context.object.data
        row = layout.row()
        row.label(text= "Set the Spacing Options")
        row = layout.split(factor= 0.45)
        row.label(text= "Character:")
        row.prop(text, "space_character", text= "")
        row = layout.split(factor= 0.45)
        row.label(text= "Word:")
        row.prop(text, "space_word", text= "")
        row = layout.split(factor= 0.45)
        row.label(text= "Line:")
        row.prop(text, "space_line", text= "")

def register():
    bpy.utils.register_class(wm_ot_text_op)
    bpy.utils.register_class(ductf_panel_ext)
    bpy.utils.register_class(OBJECT_PT_Spacing)

def unregister():
    bpy.utils.register_class(wm_ot_text_op)
    bpy.utils.unregister_class(ductf_panel_ext)
    bpy.utils.register_class(OBJECT_PT_Spacing)

if __name__ == "__main__":
    register()
